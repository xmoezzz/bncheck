import enum
import subprocess
import re
import os
import logging
import tempfile
import typing
from queue import Queue

from .basic import FunctionAnalysis, AnalysisManager, Module, Function, FunctionAnalysisManager
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation
from binaryninja.mediumlevelil import SSAVariable
from binaryninja.function import Variable
from collections import defaultdict
import abc

from analysis.ir_blk_analysis import IRBasicBlockAnalysis, IRNode
from analysis.use_define_analysis import KeyedDict

logger = logging.Logger(__name__)


StatefulType = typing.Union[MediumLevelILInstruction, SSAVariable, Variable]


class SSAFlowSensitiveStateItem(abc.ABC):

    """单个状态
    """
    @abc.abstractmethod
    def __eq__(
            self,
            other: "SSAFlowSensitiveStateItem") -> "SSAFlowSensitiveStateItem":
        pass

    @abc.abstractmethod
    def __len__(self):
        pass


class SSAFlowSensitiveDataFlowState(abc.ABC):

    @abc.abstractmethod
    def __eq__(
            self,
            other: "SSAFlowSensitiveDataFlowState") -> "SSAFlowSensitiveDataFlowState":
        pass

    @abc.abstractmethod
    def get_before_state(self):
        pass

    @abc.abstractmethod
    def get_after_state(self):
        pass

    @abc.abstractmethod
    def set_before_state(self, state):
        pass

    @abc.abstractmethod
    def set_after_state(self, state):
        pass

    @abc.abstractmethod
    def set_dirty(self):
        """如果一条指令执行前的状态被修改了，需要调用这里
        """
        pass

    @abc.abstractmethod
    def is_dirty(self):
        """这条指令的执行前的状态是否被更新了
        """
        pass

    @abc.abstractmethod
    def flush_state(self):
        """如果一条指令执行前的状态被修改了，并且后置状态也修改完毕了，需要调用这里
        """
        pass

    @abc.abstractmethod
    def is_visited(self):
        pass

    @abc.abstractmethod
    def set_visited(self):
        pass


class SSAQueueItem(object):
    def __init__(self, prev_node: IRNode, node: IRNode):
        assert isinstance(node, IRNode)

        self.prev_node = prev_node
        self.node = node

    def __hash__(self):
        prefix = 'None'
        if self.prev_node is not None:
            prefix == "%d" % (self.prev_node.ir.expr_index)
        post = "%d" % (self.node.ir.expr_index)

        return hash(prefix + "_" + post)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def replace_with(self, other):
        if hash(self) != hash(other):
            raise RuntimeError('hash not equal')

        self.prev_node = other.prev_node
        self.node = other.node
        return other


class SSAFlowSensitiveDataFlowBase(FunctionAnalysis, abc.ABC):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__states = KeyedDict(lambda x: self.get_default_state(x))
        self.__ir_blk_analysis: IRBasicBlockAnalysis = None
        self.__queue: typing.Deque[SSAQueueItem] = Queue()
        self.__in_queue: typing.Dict[int, SSAQueueItem] = dict()
        self.__function: Function = None

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self.__function: Function = function

        self.__ir_blk_analysis = fam.get_function_analysis(
            IRBasicBlockAnalysis)
        assert self.__ir_blk_analysis

        ir_node: IRNode = self.__ir_blk_analysis.get_entry()
        prev_node = None
        while len(ir_node.get_outgoing_edges()) != 0:
            outgoing_edges = ir_node.get_outgoing_edges()
            if len(outgoing_edges) == 1:
                self._trans(prev_node, ir_node)
                prev_node = ir_node
                ir_node = outgoing_edges[0]
            else:
                self._trans(prev_node, ir_node)
                """*fork*: choose one and put others into queue
                """
                prev_node = ir_node
                ir_node = outgoing_edges[0]
                """put into queue
                """
                for i in range(1, len(outgoing_edges)):
                    queue_item = SSAQueueItem(prev_node, ir_node)
                    self.__in_queue[hash(queue_item)] = queue_item
                    self.__queue.put(queue_item)

        while not self.__queue.empty():
            queue_item = self.__queue.get()
            ir_node = queue_item.node
            prev_node = queue_item.prev_node
            while len(ir_node.get_outgoing_edges()) != 0:
                outgoing_edges = ir_node.get_outgoing_edges()
                status = self._trans(prev_node, ir_node)
                if not status:
                    break

                if len(outgoing_edges) == 1:
                    prev_node = ir_node
                    ir_node = outgoing_edges[0]
                else:
                    for i in range(1, len(outgoing_edges)):
                        item = SSAQueueItem(prev_node, ir_node)
                        calc_hash = hash(item)
                        if calc_hash in self.__in_queue:
                            self.__in_queue[calc_hash].replace_with(item)
                        else:
                            self.__in_queue[calc_hash] = item
                            self.__queue.put(item)

                    #current & prev
                    prev_node = ir_node
                    ir_node = outgoing_edges[0]

    def update_var_state_before(self, node: IRNode, prev_node: IRNode) -> None:
        assert isinstance(node, IRNode)
        if isinstance(prev_node, IRNode) or prev_node is not None:
            raise TypeError()

        """上一条指令的执行之后的状态是否和当前指令执行之前的状态相等
        """
        prev = self.__states[prev_node].get_after_state()
        curr = self.__states[node].get_before_state()
        if prev != curr:
            """直接更新，因为当前指令还没被执行
            """
            self.__states[node].set_before_state(prev)
            if self.__states[node].is_visited():
                self.__states[node].set_dirty()
            return True

        return False

    def update_var_state_after(
            self,
            node: IRNode,
            before_state: SSAFlowSensitiveStateItem,
            ir_state: SSAFlowSensitiveStateItem) -> None:

        assert isinstance(before_state, SSAFlowSensitiveStateItem)
        assert isinstance(ir_state, SSAFlowSensitiveStateItem)
        assert isinstance(node, IRNode)

        """state : 执行本条IR产生的新state
           返回True:当前迭代还需要继续走下去
           返回False:当前迭代到此为止
        """

        before_state = self.__states[node].get_before_state()
        after_state = self.__states[node].get_after_state()

        if self.__states[node].is_visited() == False:
            new_state = self.meet(ir_state, before_state)
            if new_state != before_state:
                self.__states[node].set_after_state(new_state)
            self.__states[node].set_visited()
            return True

        # 不是第一次访问了
        # 没被更新则退出
        if self.__states[node].is_dirty() == False:
            return False

        new_state = self.meet(ir_state, before_state)
        if new_state == after_state:
            self.__states[node].flush_state()
            return False

        self.__states[node].set_after_state()
        self.__states[node].flush_state()
        return True

    @abc.abstractmethod
    def meet(
            self,
            node: IRNode,
            ir_state,
            *
            args: typing.Sequence['SSAFlowSensitiveStateItem']) -> 'SSAFlowSensitiveStateItem':
        raise NotImplementedError()

    @abc.abstractmethod
    def get_default_item_state(
            self, expr_index: int) -> SSAFlowSensitiveStateItem:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_default_state(
            self,
            expr_index: int) -> SSAFlowSensitiveDataFlowState:
        raise NotImplementedError()

    @abc.abstractmethod
    def trans(self, node: IRNode,
              prev_node: IRNode) -> typing.Tuple[bool, bool]:
        """
        user defined trans function, should return True
        """
        raise NotImplementedError()

    def _trans(self, node: IRNode, prev_node: IRNode) -> bool:

        assert isinstance(node, IRNode)

        status, need_update = self.trans(node, prev_node)
        if status:
            return need_update

        self.update_var_state_before(node, prev_node)
        need_update = self.update_var_state_after(
            node, prev_node, self.get_default_item_state(
                node.ir.expr_index))
        return need_update

    def get_state_of(self, expr_index: int) -> SSAFlowSensitiveDataFlowState:
        # 每个状态记录下before和after两个信息
        node = self.__ir_blk_analysis.get_ir_node_at(expr_index)
        if node is None:
            return None

        return self.__states[node]
