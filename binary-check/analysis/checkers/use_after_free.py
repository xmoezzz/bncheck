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
1. find those free like function
2. detect all functions that return a dangling pointer
3. do inter-procedure analysis and use dangling pointer, or use after free like function (TODO)
"""


class UseAfterFreeChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "UseAfterFree"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        super().run_on_module(module, mam)

        for func in module.functions:
            ssa_func = func.mlil.ssa_form
            if ssa_func is None:
                continue

            var_freed_inst = []
            for inst in ssa_func.instructions:
                if inst.operation not in [
                        MediumLevelILOperation.MLIL_CALL_SSA,
                        MediumLevelILOperation.MLIL_TAILCALL_SSA]:
                    continue
                for ssa_var in mam.get_module_analysis(
                        FreeFunctionDetectionAnalysis).get_freed_arg_ssa_list(inst):
                    var_freed_inst.append((ssa_var, inst))

            if len(var_freed_inst) <= 0:
                continue
            use_def: SSAUseDefineAnalysis = mam.get_function_analysis(
                SSAUseDefineAnalysis, func)
            dom_tree: DominatorTreeAnalysis = mam.get_function_analysis(
                DominatorTreeAnalysis, func)
            equ_ana: EquivalentAnalysis = mam.get_function_analysis(
                EquivalentAnalysis, func)
            cfg_ana: CFGAnalysis = mam.get_function_analysis(
                CFGAnalysis, func)

            for inst in use_def.get_all_variables():
                if not isinstance(inst, MediumLevelILInstruction):
                    continue
                #print("")
                #print(inst, "???")

                for freed, freed_inst in var_freed_inst:
                    # if (dom_tree.does_dominate(freed_inst, inst, True) ==
                    # True or dom_tree.does_post_dominate(inst, freed_inst,
                    # True) == True) and equ_ana.are_equivalent(freed, inst,
                    # inst):
                    if dom_tree.does_dominate( freed_inst, inst, True) and equ_ana.are_equivalent(freed, inst, inst):
                        self.report((freed_inst, inst, inst.function.source_function.name))
                    elif dom_tree.does_post_dominate(inst, freed_inst, True) and (not cfg_ana.has_path(inst, freed_inst)) and equ_ana.are_congruent(freed, inst):
                        for ssa_var in inst.vars_read:
                            def_inst = use_def.get_definition_instruction(ssa_var)
                            if def_inst is None:
                                continue
                            if cfg_ana.has_path(freed_inst, def_inst):
                                break
                        else:
                            self.report((freed_inst, inst, inst.function.source_function.name))
