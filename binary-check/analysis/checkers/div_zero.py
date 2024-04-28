from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.module_info_analysis import ModuleInfoAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.value_set_analysis import SimpleValueSetAnalysis
from analysis.utils import get_call_ssa_instructions_to

from binaryninja import MediumLevelILOperation, MediumLevelILInstruction

import binaryninja
import typing
import logging

class DivZeroChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "DivZero"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        for func in module.functions:
            for blk in func.mlil.ssa_form:
                for insn in blk:
                    if insn.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
                        continue
                    src_insn : MediumLevelILInstruction = insn.src
                    if src_insn.operation not in(
                        MediumLevelILOperation.MLIL_DIVS,
                        MediumLevelILOperation.MLIL_DIVU
                        ):
                        continue
                    if self.__on_check_div(func, src_insn.right):
                        self.report(insn)

    def __on_check_div(self, func : Function, right_insn : MediumLevelILInstruction)->bool:
        value_set_analysis : SimpleValueSetAnalysis = self.__mam.get_function_analysis(SimpleValueSetAnalysis, func)
        if right_insn.operation != MediumLevelILOperation.MLIL_VAR_SSA:
            return False
        vals =  list(value_set_analysis.get_state_of(right_insn.src))
        for val in vals:
            """我们需要路径敏感?
            """
            if val == 0:
                return True
        return False

