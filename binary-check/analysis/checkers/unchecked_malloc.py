from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis
from analysis.checkers.cpu64.cpu64_equivalent_analysis import Cpu64EquivalentAnalysis as EquivalentAnalysis
from analysis.utils import get_call_ssa_instructions_to

from binaryninja import MediumLevelILOperation, MediumLevelILInstruction

import typing
import logging

logger = logging.getLogger(__name__)


class UncheckedMallocReportItem(object):
    def __init__(self, insn : MediumLevelILInstruction):
        self.xalloc_insn : MediumLevelILInstruction = insn
        self.owner : Function = insn.function.source_function
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        return "=====================\nuninitialized allocation : (%s)\nfunction : (%s)\n=====================\n\n" % (
            self.xalloc_insn,
            self.owner
        )
        
        

class UncheckedMallocChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "UncheckedMalloc"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        calls = get_call_ssa_instructions_to(module, "malloc")
        calls.extend(get_call_ssa_instructions_to(module, "calloc"))
        calls.extend(get_call_ssa_instructions_to(module, "realloc"))
        for call_insn in calls:
            output_insn : MediumLevelILInstruction = call_insn.output
            if len(output_insn.dest) < 0:
                continue
            ret_ssa = output_insn.dest[0]
            func : Function = call_insn.function.source_function
            equivalent_analysis : EquivalentAnalysis = mam.get_function_analysis(EquivalentAnalysis, func)
            dominator_tree : DominatorTreeAnalysis = mam.get_function_analysis(DominatorTreeAnalysis, func)
            left_checked = False
            right_checked = False
            for blk in func.mlil.ssa_form:
                if left_checked or right_checked:
                    break
                for insn in blk:
                    if insn.operation != MediumLevelILOperation.MLIL_IF:
                        continue
                    cmp_insn : MediumLevelILOperation = insn.condition
                    if not dominator_tree.does_dominate(call_insn, insn):
                        continue
                    left_insn  : MediumLevelILInstruction = cmp_insn.left
                    right_insn : MediumLevelILInstruction = cmp_insn.right
                    
                    if left_insn.operation != MediumLevelILOperation.MLIL_VAR_SSA and \
                        right_insn.operation != MediumLevelILOperation.MLIL_VAR_SSA:
                        continue
                    """malloc之后一般都是马上检查的，不太可能会在子调用再去做检查的
                       TODO : wrapper function?
                    """
                    if left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                        if equivalent_analysis.are_equivalent(left_insn.src, ret_ssa, insn):
                            left_checked = True
                    if right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:

                        if equivalent_analysis.are_equivalent(right_insn.src, ret_ssa, insn):
                            right_checked = True
            
            if left_checked == False and right_checked == False:
                self.report(UncheckedMallocReportItem(call_insn))