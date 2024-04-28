from .basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, FunctionAnalysis, ModuleAnalysis, Module
from .use_define_analysis import SSAUseDefineAnalysis, StandardSSAVariable
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from binaryninja.enums import ILBranchDependence
import copy

import abc

import typing
from queue import Queue
from collections import defaultdict

from .utils import get_call_ssa_instructions_to

from .equivalent_analysis import EquivalentAnalysis


class FreeFunctionDetectionAnalysis(ModuleAnalysis, abc.ABC):
    """用于寻找和Free函数类似的函数"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def initialize(self, module: Module, mam: ModuleAnalysisManager):
        super().initialize(module, mam)
        # function name or addr -> set[arg_index]
        self.__function_freeing_arg = defaultdict(set)
        self.__inst_freeing_arg = defaultdict(set)

    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        super().run_on_module(module, mam)
        visited = set()
        q = Queue()

        def put(name_or_addr, arg_index):
            if (name_or_addr, arg_index) in visited:
                return
            q.put((name_or_addr, arg_index))
            visited.add((name_or_addr, arg_index))
            self.__function_freeing_arg[name_or_addr].add(arg_index)

        put("free", 0)
        put("_free", 0)
        #put("realloc", 0)
        #put("_realloc", 0)

        func_arg_dep_set = {}

        while not q.empty():
            name_or_addr, arg_index = q.get()
            for call_inst in get_call_ssa_instructions_to(
                    module, name_or_addr):
                if not arg_index < len(call_inst.params):
                    continue
                freed_ssa_var = call_inst.params[arg_index]

                self.__inst_freeing_arg[call_inst].add(arg_index)

                func = call_inst.function.source_function
                var_paramters = func.parameter_vars.vars
                equ_analysis = mam.get_function_analysis(
                    EquivalentAnalysis, func)

                for parameter_index, var in enumerate(var_paramters):
                    ssa_var = SSAVariable(var, 0)
                    if equ_analysis.are_equivalent(ssa_var, freed_ssa_var):

                        branch_dep_dict = {}
                        # if all branch dependence are .... only related to
                        # pointer it self (say pointer == NULL)
                        for inst_id, branch_dep in call_inst.branch_dependence.items():
                            inst = call_inst.function[inst_id]
                            if inst.operation == MediumLevelILOperation.MLIL_IF and inst.condition.operation in [
                                    MediumLevelILOperation.MLIL_CMP_E,
                                    MediumLevelILOperation.MLIL_CMP_NE,
                                    MediumLevelILOperation.MLIL_CMP_SGE,
                                    MediumLevelILOperation.MLIL_CMP_SGT,
                                    MediumLevelILOperation.MLIL_CMP_SLE,
                                    MediumLevelILOperation.MLIL_CMP_SLT,
                                    MediumLevelILOperation.MLIL_CMP_UGE,
                                    MediumLevelILOperation.MLIL_CMP_UGT,
                                    MediumLevelILOperation.MLIL_CMP_ULE,
                                    MediumLevelILOperation.MLIL_CMP_ULT]:
                                if equ_analysis.are_equivalent(
                                        inst.condition.left, ssa_var) or equ_analysis.are_equivalent(
                                        inst.condition.right, ssa_var):
                                    continue  # this if not related
                            branch_dep_dict[inst_id] = branch_dep

                        if (func, parameter_index) not in func_arg_dep_set:
                            func_arg_dep_set[(
                                func, parameter_index)] = branch_dep_dict
                        else:
                            original_cons = func_arg_dep_set[(
                                func, parameter_index)]
                            for inst_id in list(original_cons.keys()):
                                if inst_id not in branch_dep_dict:
                                    original_cons.pop(inst_id)
                            for inst_id, branch_dep in branch_dep_dict.items():
                                if inst_id not in original_cons:
                                    continue
                                if ILBranchDependence.FalseBranchDependent in [
                                        branch_dep,
                                        original_cons[inst_id]] and ILBranchDependence.TrueBranchDependent in [
                                        branch_dep,
                                        original_cons[inst_id]]:
                                    original_cons.pop(inst_id)

                        if len(func_arg_dep_set[(func, parameter_index)]) == 0:
                            put(func.start, parameter_index)

    def get_freed_arg_index_list(
            self, inst: MediumLevelILInstruction) -> typing.List[int]:
        assert isinstance(inst, MediumLevelILInstruction)
        assert inst.operation in [
            MediumLevelILOperation.MLIL_CALL_SSA,
            MediumLevelILOperation.MLIL_TAILCALL_SSA]

        if inst in self.__inst_freeing_arg:
            return list(self.__inst_freeing_arg[inst])
        return []

    def get_freed_arg_ssa_list(self, inst) -> typing.List[StandardSSAVariable]:
        """
        返回该条call指令free掉的所有表达式
        """
        return list(
            map(lambda x: inst.params[x], self.get_freed_arg_index_list(inst)))
