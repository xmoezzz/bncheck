import binaryninja
import typing
import logging
import analysis.utils

from analysis.basic import FunctionAnalysisManager, Function, Module
from analysis.flow_sensitive_dataflow_analysis import SSAFlowSensitiveDataFlowBase, SSAFlowSensitiveDataFlowState, \
    IRNode
from binaryninja import MediumLevelILOperation, MediumLevelILInstruction, SSAVariable, Variable


logger = logging.getLogger(__name__)


class VarDefineState(set):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ssa_vars: typing.Dict[str, SSAVariable] = dict()

    def add(self, *args, **kwargs):
        super().add(*args, **kwargs)
        for v in args:
            if isinstance(v, SSAVariable):
                self._ssa_vars[v.var.name] = v

    def has_ssa_define(self, v):
        if not isinstance(v, SSAVariable):
            return None

        if v.name in self._ssa_vars:
            item = self._ssa_vars.pop(v.name)
            return item

        return None


class FlowSensitiveVarDefineState(SSAFlowSensitiveDataFlowState):
    def __init__(self):
        self._before_state = VarDefineState()
        self._after_state = VarDefineState()
        self._is_dirty = False
        self._visit_state = False

    def __eq__(self, other: FlowSensitiveVarDefineState):
        if other is None:
            return False

        assert isinstance(other, FlowSensitiveVarDefineState)
        if self._before_state != other.get_before_state():
            return False

        if self._after_state != other.get_after_state():
            return False

        return True

    def get_before_state(self):
        return self._before_state

    def get_after_state(self):
        return self._after_state

    def set_before_state(self, state):
        assert isinstance(state, VarDefineState)
        self._before_state = state

    def set_after_state(self, state):
        assert isinstance(state, VarDefineState)
        self._after_state = state

    def set_dirty(self):
        self._is_dirty = True

    def flush_state(self):
        self._is_dirty = False

    def is_visited(self):
        return self._visit_state

    def set_visited(self):
        self._visit_state = True


class SSAFlowSensitiveDataFlowAnalysis(SSAFlowSensitiveDataFlowBase):
    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self._func = function
        self._irfunc = function.mlil.ssa_form
        self._fam = fam
        super().run_on_function(function, fam)

    def get_default_state(self):
        return FlowSensitiveVarDefineState()

    def meet(self, ir_state: VarDefineState, *
             args: typing.Sequence[VarDefineState]) -> VarDefineState:
        """当前指令会定义什么

        Arguments:
            node {IRNode} -- [description]

        Returns:
            VarDefineState -- [description]
        """
        state = VarDefineState()
        for v in args:
            if not isinstance(v, VarDefineState):
                continue
            state |= v

        for s in ir_state:
            if isinstance(s, SSAVariable):
                item = state.has_ssa_define(s)
                if item is not None:
                    state.remove(item)
                    state.add(s)
            else:
                state.add(s)

        return state

    def trans(self, node: IRNode,
              prev_node: IRNode) -> typing.Tuple[bool, bool]:
        """translate current

        Arguments:
            node {IRNode} -- [description]
            prev_node {IRNode} -- [description]

        Returns:
            typing.Tuple[bool, bool] -- [description]
        """
        status = False
        need_update = False
        ir_state = VarDefineState()

        if node.ir.operation in (
                MediumLevelILOperation.MLIL_CALL_SSA,
                MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
                MediumLevelILOperation.MLIL_TAILCALL_SSA):
            call_output_insn = node.ir.output
            for var in call_output_insn.dest:
                ir_state.add(var)
            status = True

        elif node.ir.operation in (
                MediumLevelILOperation.MLIL_SET_VAR,
                MediumLevelILOperation.MLIL_SET_VAR_FIELD,
                MediumLevelILOperation.MLIL_SET_VAR_SSA,
                MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD):
            ir_state.add(node.ir.dest)
            status = True

        elif node.ir.operation == MediumLevelILOperation.MLIL_VAR_PHI:
            ir_state.add(node.ir.dest)
            status = True

        if not status:
            return status, need_update

        self.update_var_state_before(node, prev_node)
        need_update = self.update_var_state_after(
            node, prev_node, self.get_default_item_state(
                node.ir.expr_index))
        return status, need_update
