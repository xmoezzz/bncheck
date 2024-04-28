import enum
import subprocess
import re
import os
import logging
import tempfile
import typing
from queue import Queue

from .basic import FunctionAnalysis, AnalysisManager, Module, Function, FunctionAnalysisManager, Analysis, ModuleAnalysis, ModuleAnalysisManager
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation
from binaryninja.mediumlevelil import SSAVariable
from binaryninja.function import Variable
from collections import defaultdict
import abc
from .utils import get_call_ssa_dest_addr, get_call_ssa_instructions_to

from .use_define_analysis import SSAUseDefineAnalysis, KeyedDict, StandardSSAVariable

logger = logging.Logger(__name__)


StatefulType = typing.Union[MediumLevelILInstruction, SSAVariable, Variable]


class SSADataFlowState(abc.ABC):
    @abc.abstractmethod
    def __eq__(self, other: 'SSADataFlowState') -> 'SSADataFlowState':
        pass


class SSADataFlowAnalysisOperationBase(Analysis, abc.ABC):
    @abc.abstractmethod
    def meet(self, target_ssa_var: SSAVariable, *
             args: typing.Sequence['SSADATAFlowState']) -> 'SSADataFlowState':
        pass

    @abc.abstractmethod
    def join(self, target_ssa_var: SSAVariable, *
             args: typing.Sequence['SSADATAFlowState']) -> 'SSADataFlowState':
        pass

    @abc.abstractmethod
    def get_default_state(self, var: StandardSSAVariable) -> SSADataFlowState:
        pass

    @abc.abstractmethod
    def trans(self, inst: MediumLevelILInstruction) -> bool:
        """
        user defined trans function, should return True
        """
        pass


class SSADataFlowAnalysisBase(
        SSADataFlowAnalysisOperationBase,
        FunctionAnalysis,
        abc.ABC):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__states = KeyedDict(lambda x: self.get_default_state(x))
        self.__use_def_analysis: SSAUseDefineAnalysis = None
        self.__in_queue: typing.Set[StandardSSAVariable] = set()
        self.__queue: typing.Deque[StandardSSAVariable] = Queue()
        self.__function: Function = None

    def initialize(self, function: Function, fam: FunctionAnalysisManager):
        super().initialize(function, fam)
        self.__function: Function = function
        self.__use_def_analysis = fam.get_function_analysis(
            SSAUseDefineAnalysis)
        assert self.__use_def_analysis

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)

        # for var in self.__use_def_analysis.get_all_variables():
        #   if isinstance(var, MediumLevelILInstruction):
        #       if var.il_basic_block == bbl:
        #           self._trans(var)
        # 这里我们不能考虑如上方案，因为比如做Constant
        # Folding的时候，我们可能需要关注ConstantInt开始迭代，而不是程序开始的基本块

        for var in self.__use_def_analysis.get_all_variables():
            if isinstance(var, MediumLevelILInstruction):
                self._trans(var)

        while not self.__queue.empty():
            var = self.__queue.get()
            self.__in_queue.remove(var)
            assert len(self.__in_queue) == self.__queue.qsize()
            self._trans(var)

            #users = self.__use_def_analysis.get_users_of(var)
            # for user in users:
            #    if isinstance(user, MediumLevelILInstruction):
            #        self._trans(user)

    def update_var_state(self, var: StandardSSAVariable,
                         state: SSADataFlowState) -> None:

        assert isinstance(state, SSADataFlowState)

        # FIXME: we should add this, but this break tests...
        state = self.join(var, state, self.__states[var])

        if self.__states[var] != state:
            # 由于我们这里不是Flow-Sensitive Dataflow，所有结果依赖于SSAVariable.
            self.__states[var] = state
            for user in self.__use_def_analysis.get_users_of(var):
                if user not in self.__in_queue:
                    self.__in_queue.add(user)
                    self.__queue.put(user)

    def _trans(self, inst: MediumLevelILInstruction):

        assert isinstance(inst, MediumLevelILInstruction), "current : %s %s" % (
            inst, type(inst))

        if self.trans(inst):
            return

        if inst.operation in [MediumLevelILOperation.MLIL_SET_VAR_SSA]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst.dest, src_state)
            return
        if inst.operation in [MediumLevelILOperation.MLIL_SET_VAR]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst.dest, src_state)
            return
        elif inst.operation in [MediumLevelILOperation.MLIL_VAR_SSA]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst, src_state)
            return
        elif inst.operation in [MediumLevelILOperation.MLIL_VAR]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst, src_state)
            return
        elif inst.operation == MediumLevelILOperation.MLIL_VAR_PHI:
            src_states = list(
                map(lambda var: self.get_state_of(var), inst.src))
            meet_state = self.meet(inst.dest, *src_states)
            self.update_var_state(inst.dest, meet_state)
            return
        elif inst.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            self.update_var_state(inst.dest, self.get_state_of(inst.src))
            return
        elif inst.operation == MediumLevelILOperation.MLIL_VAR_ALIASED:
            self.update_var_state(inst, self.get_state_of(inst.src))
            return
        elif inst.operation == MediumLevelILOperation.MLIL_MEM_PHI:
            for new_ssa_var in self.__use_def_analysis.get_all_ssa_var_in_memory_version(
                    inst.dest_memory):
                old_ssa_vars = []
                for old_version in inst.src_memory:
                    old_ssa_var = self.__use_def_analysis.get_ssa_var_of_memory_version(
                        old_version, new_ssa_var)
                    old_ssa_vars.append(old_ssa_var)
                new_state = self.meet(
                    new_ssa_var, *list(map(lambda ssa_var: self.get_state_of(ssa_var), old_ssa_vars)))
                self.update_var_state(new_ssa_var, new_state)
            return
        #assert False, "Undefined %s for %s" % (inst.operation, self)

        # TODO:Some default trans

    def get_state_of(self, var: StandardSSAVariable) -> SSADataFlowState:
        return self.__states[var]


class SSAInterprocedureDataFlowAnalysisBase(
        SSADataFlowAnalysisOperationBase,
        ModuleAnalysis,
        abc.ABC):

    """Be care of recusive function....int f(int a, int b) {f(a+1, b+1);}"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__states = KeyedDict(lambda x: self.get_default_state(x))
        self.__in_queue: typing.Set[StandardSSAVariable] = set()
        self.__queue: typing.Deque[StandardSSAVariable] = Queue()

    def initialize(self, module: Module, mam: ModuleAnalysisManager):
        super().initialize(module, mam)
        self.__module: Module = module
        self.__mam: ModuleAnalysisManager = mam

    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        super().run_on_module(module, mam)

        for function in module.functions:
            if function.mlil.ssa_form is None:
                continue
            for var in self.__mam.get_function_analysis(
                    SSAUseDefineAnalysis, function).get_all_variables():
                if isinstance(var, MediumLevelILInstruction):
                    self._trans(var)

        while not self.__queue.empty():
            var = self.__queue.get()
            self.__in_queue.remove(var)
            assert len(self.__in_queue) == self.__queue.qsize()
            self._trans(var)

            #users = self.__use_def_analysis.get_users_of(var)
            # for user in users:
            #    if isinstance(user, MediumLevelILInstruction):
            #        self._trans(user)

    def update_var_state(self, var: StandardSSAVariable,
                         state: SSADataFlowState) -> None:

        assert isinstance(state, SSADataFlowState)
        state = self.join(var, state, self.__states[var])

        v = var
        if isinstance(var, SSAVariable):
            v = var.var
        if isinstance(v, Variable):
            func = v.function
        else:
            func = v.function.source_function

        use_def_analysis = self.__mam.get_function_analysis(
            SSAUseDefineAnalysis, func)

        if self.__states[var] != state:
            # 由于我们这里不是Flow-Sensitive Dataflow，所有结果依赖于SSAVariable.
            self.__states[var] = state
            for user in use_def_analysis.get_users_of(var):
                if user not in self.__in_queue:
                    self.__in_queue.add(user)
                    self.__queue.put(user)

    def _trans(self, inst: MediumLevelILInstruction):

        assert isinstance(inst, MediumLevelILInstruction), "current : %s %s" % (
            inst, type(inst))

        if self.trans(inst) and (
            inst.operation not in [
                MediumLevelILOperation.MLIL_CALL_SSA,
                MediumLevelILOperation.MLIL_RET,
                MediumLevelILOperation.MLIL_TAILCALL_SSA]):
            return

        if inst.operation in [MediumLevelILOperation.MLIL_SET_VAR_SSA]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst.dest, src_state)
            return
        elif inst.operation in [MediumLevelILOperation.MLIL_SET_VAR]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst.dest, src_state)
            return
        elif inst.operation in [MediumLevelILOperation.MLIL_VAR_SSA]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst, src_state)
            return
        elif inst.operation in [MediumLevelILOperation.MLIL_VAR]:
            src_state = self.get_state_of(inst.src)
            self.update_var_state(inst, src_state)
            return
        elif inst.operation == MediumLevelILOperation.MLIL_VAR_PHI:
            src_states = list(
                map(lambda var: self.get_state_of(var), inst.src))
            meet_state = self.meet(inst.dest, *src_states)
            self.update_var_state(inst.dest, meet_state)
            return
        elif inst.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            self.update_var_state(inst.dest, self.get_state_of(inst.src))
            return
        elif inst.operation == MediumLevelILOperation.MLIL_VAR_ALIASED:
            self.update_var_state(inst, self.get_state_of(inst.src))
            return
        elif inst.operation == MediumLevelILOperation.MLIL_MEM_PHI:
            use_def_analysis = self.__mam.get_function_analysis(
                SSAUseDefineAnalysis, inst.function.source_function)
            for new_ssa_var in use_def_analysis.get_all_ssa_var_in_memory_version(
                    inst.dest_memory):
                old_ssa_vars = []
                for old_version in inst.src_memory:
                    old_ssa_var = use_def_analysis.get_ssa_var_of_memory_version(
                        old_version, new_ssa_var)
                    old_ssa_vars.append(old_ssa_var)
                new_state = self.meet(
                    new_ssa_var, *list(map(lambda ssa_var: self.get_state_of(ssa_var), old_ssa_vars)))
                self.update_var_state(new_ssa_var, new_state)
            return

        if inst.operation in [
                MediumLevelILOperation.MLIL_CALL_SSA,
                MediumLevelILOperation.MLIL_TAILCALL_SSA]:
            def doit():
                callee_addr = get_call_ssa_dest_addr(self.__module, inst)
                if callee_addr is None:
                    return

                callee_function: Function = self.__module.get_function_at(
                    callee_addr)
                if callee_function is None:
                    return

                if callee_function.mlil is None or callee_function.mlil.ssa_form is None:
                    return

                callee_ssa_function = callee_function.mlil.ssa_form
                var_paramters = callee_function.parameter_vars.vars

                calling_instructions = get_call_ssa_instructions_to(
                    self.__module, callee_addr)
                if inst not in calling_instructions:
                    return  # FIXME: 这是由于binaryninja查找callee找不到，这说明我们的callgraph不全

                ssa_paramters = list(
                    map(lambda var: SSAVariable(var, 0), var_paramters))

                for parameter_index, ssa_paramter in enumerate(ssa_paramters):
                    source_state_list = []
                    for calling_ssa_inst in calling_instructions:
                        if parameter_index >= len(calling_ssa_inst.params):
                            continue
                        source_state_list.append(
                            self.__states[calling_ssa_inst.params[parameter_index]])
                    if len(source_state_list) > 0:
                        meeted_state = self.meet(
                            ssa_paramter, *source_state_list)
                        self.update_var_state(ssa_paramter, meeted_state)
            doit()

        if inst.operation in [
                MediumLevelILOperation.MLIL_RET,
                MediumLevelILOperation.MLIL_TAILCALL_SSA]:
            callee_addr = inst.function.source_function.start
            if callee_addr is None:
                return

            source_states = []
            for inst in inst.function.instructions:
                if inst.operation == MediumLevelILOperation.MLIL_RET and len(
                        inst.src) >= 1:
                    source_states.append(self.get_state_of(inst.src[0]))
                if inst.operation == MediumLevelILOperation.MLIL_TAILCALL_SSA and len(
                        inst.output.dest) >= 1:
                    source_states.append(
                        self.get_state_of(
                            inst.output.dest[0]))
            if len(source_states) <= 0:
                return

            calling_instructions = get_call_ssa_instructions_to(
                self.__module, callee_addr)
            for calling_instruction in calling_instructions:
                if len(calling_instruction.output.dest) >= 1:
                    ssa_var = calling_instruction.output.dest[0]
                    meeted_state = self.meet(ssa_var, *source_states)
                    self.update_var_state(ssa_var, meeted_state)

    def get_state_of(self, var: StandardSSAVariable) -> SSADataFlowState:
        return self.__states[var]
