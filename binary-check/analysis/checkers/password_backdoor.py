from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.utils import get_call_ssa_instructions_to
from utils.base_tool import safe_str, get_callee_name

from binaryninja import MediumLevelILOperation, MediumLevelILInstruction, \
    SSAVariable

import typing
import logging

logger = logging.getLogger(__name__)


class PasswordBackdoorReport(object):
    def __init__(self, func : Function, source_insn : MediumLevelILInstruction, dest_insn : MediumLevelILInstruction, const_offset : int):
        self.func : Function = func
        self.source_insn : MediumLevelILInstruction = source_insn
        self.dest_insn : MediumLevelILInstruction =  dest_insn
        self.const_offset : int = const_offset

class PasswordBackdoorChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "PasswordBackdoor"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        self.__cmp_funcs = {
            "strcmp" : [1, 1],
            "memcmp" : [1, 1],
            "strncmp" : [1, 1],
            "strcasecmp" : [1, 1],
            "strncasecmp" : [1, 1]
        }
        calls = get_call_ssa_instructions_to(module, "getenv")
        for call_insn in calls:
            params : typing.List[MediumLevelILInstruction] = call_insn.params
            output_insn : MediumLevelILInstruction = call_insn.output
            if len(params) < 1:
                continue
            if len(output_insn.dest) < 1:
                continue
            env_name_insn : MediumLevelILInstruction = params[0]
            if env_name_insn.operation not in (
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR
                ):
                continue

            env_name, _ = safe_str(module, env_name_insn.constant)
            if not isinstance(env_name, str):
                continue
            if env_name != "HTTP_AUTHORIZATION":
                continue

    
    def __on_check_hardcoded(self, insn : MediumLevelILInstruction, retv : SSAVariable):
        function : Function = insn.function.source_function
        _dominator_tree_analysis : DominatorTreeAnalysis  = self.__mam.get_function_analysis(DominatorTreeAnalysis, function)
        _equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(EquivalentAnalysis, function)
        for blk in function.mlil.ssa_form:
            for inst in blk:
                if not _dominator_tree_analysis.does_dominate(
                    insn,
                    inst
                    ):
                    continue
                if  inst.operation not in (
                    MediumLevelILOperation.MLIL_CALL_SSA,
                    MediumLevelILOperation.MLIL_TAILCALL_SSA
                    ):
                    continue
                callee_name = get_callee_name(self.__module, inst)
                if callee_name not in self.__cmp_funcs:
                    continue
                check_func : typing.List[int] = self.__cmp_funcs[callee_name]
                if len(inst.params) < len(check_func):
                    continue
                idx = 0
                bconst_source = False
                const_source = None
                bvar_source = False
                for param_insn in inst.params:
                    if idx >= len(check_func):
                        break
                    if bconst_source and bvar_source:
                        break
                    if check_func[idx] != 0 and bconst_source == False:
                        if param_insn.operation in (
                            MediumLevelILOperation.MLIL_CONST,
                            MediumLevelILOperation.MLIL_CONST_PTR
                            ):
                            bconst_source = True
                            const_source = param_insn.constant
                    if check_func[idx] != 0 and bvar_source == False:
                        if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                            src_var : SSAVariable = param_insn.src
                            if _equivalent_analysis.are_equivalent(src_var, retv, inst):
                                bvar_source = True
                    idx += 1
                
                if bconst_source and bvar_source:
                    self.report(PasswordBackdoorReport(
                        insn.function.source_function,
                        insn,
                        inst,
                        const_source
                    ))
                


    
        