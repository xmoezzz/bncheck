from .basic import CheckerBase
from ..basic import Function, Module, ModuleAnalysisManager, FunctionAnalysisManager, AnalysisManager
from ..dataflow_analysis import SSADataFlowState, SSADataFlowAnalysisOperationBase, SSADataFlowAnalysisBase
from ..value_set_analysis import SimpleValueSetAnalysis
from ..use_define_analysis import StandardSSAVariable
from binaryninja.types import Symbol
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from binaryninja.enums import VariableSourceType
import typing
from ..utils import get_call_ssa_instructions_to, get_call_ssa_dest_name

from ..use_define_analysis import SSAUseDefineAnalysis
from ..dominator_tree import DominatorTreeAnalysis
from ..equivalent_analysis import EquivalentAnalysis
from ..cfg_analysis import CFGAnalysis

from collections import defaultdict
import queue

from ..free_function_detection_analysis import FreeFunctionDetectionAnalysis

"""
The basic idea is:
1. If a function has signed compare  say x signed <= 100
2. This is the only check about x
3. And x does't not checked it's lower bound
"""


class SignedCompareChecker(CheckerBase):
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        super().run_on_module(module, mam)

        for func in module.functions:
            ssa_func = func.mlil.ssa_form
            if ssa_func is None:
                continue

            use_def: SSAUseDefineAnalysis = mam.get_function_analysis(
                SSAUseDefineAnalysis, func)
            dom_tree: DominatorTreeAnalysis = mam.get_function_analysis(
                DominatorTreeAnalysis, func)
            equ_ana: EquivalentAnalysis = mam.get_function_analysis(
                EquivalentAnalysis, func)
            cfg_ana: CFGAnalysis = mam.get_function_analysis(
                CFGAnalysis, func)

            input_ssa_vars: typing.Set[SSAVariable] = set() # 来源于函数外的尚未安全的ssa_vars
            var_paramters = func.parameter_vars.vars

            for parameter_index, var in enumerate(var_paramters):
                ssa_var = SSAVariable(var, 0)
                input_ssa_vars.add(ssa_var)
            
            # removing those checked the lower bound
            for inst in use_def.get_all_variables():
                if not isinstance(inst, MediumLevelILInstruction):
                    continue

                if inst.operation in [
                    MediumLevelILOperation.MLIL_CMP_E,
                    MediumLevelILOperation.MLIL_CMP_NE,
                    MediumLevelILOperation.MLIL_CMP_UGE,
                    MediumLevelILOperation.MLIL_CMP_UGT,
                    MediumLevelILOperation.MLIL_CMP_ULE,
                    MediumLevelILOperation.MLIL_CMP_ULT,
                    ]:
                    for input_ssa_var in list(input_ssa_vars):
                        # be careful, we are delete items during iteration
                        if equ_ana.are_equivalent(inst.left, input_ssa_var, inst) or equ_ana.are_equivalent(inst.right, input_ssa_var, inst):
                            input_ssa_vars.remove(input_ssa_var)

            # removing those checked the lower bound
            for inst in use_def.get_all_variables():
                if not isinstance(inst, MediumLevelILInstruction):
                    continue

                if inst.operation in [
                    MediumLevelILOperation.MLIL_CMP_SGE,
                    MediumLevelILOperation.MLIL_CMP_SGT,
                    MediumLevelILOperation.MLIL_CMP_SLE,
                    MediumLevelILOperation.MLIL_CMP_SLT,
                    ]:
                    left = inst.left
                    right = inst.right

                    for input_ssa_var in list(input_ssa_vars):
                        # we found there is a check for upper bound
                        if not (right.operation in [
                                MediumLevelILOperation.MLIL_CONST,
                                MediumLevelILOperation.MLIL_CONST_PTR,
                                ] and \
                            right.constant > 0):
                            continue

                        if equ_ana.are_equivalent(left, input_ssa_var, inst):
                            input_ssa_vars.remove(input_ssa_var)
                            self.report((input_ssa_var, func, func.name))
