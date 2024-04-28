from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.module_info_analysis import ModuleInfoAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation
from utils.base_tool import safe_str, get_callee_name

import binaryninja
import typing
import logging

logger = logging.getLogger(__name__)

class UrlFilterIssue(object):
    def __init__(self, func : Function, httpd_name : str):
        self.__func : Function = func
        self.__name : str = httpd_name
    
    @property
    def function(self)->Function:
        return self.__func
    
    @property
    def httpd_name(self)->str:
        return self.__name

class UrlFilterChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "UrlFilter"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        self.__module_info_analysis : ModuleInfoAnalysis = mam.get_module_analysis(ModuleInfoAnalysis, module)
        self.__handler = {
            "micro_httpd" : self.__run_on_micro_httpd
        }
        self.__known_filters : [
            "..",
            "../",
            "/../",
            "/.."
        ]

        all_libraries : typing.List[str] = self.__module_info_analysis.all_libraries()
        hit = False
        for lib in all_libraries:
            if lib in self.__handler:
                self.__handler[lib]()
                hit = True
        
        if not hit:
            self.__run_on_general()
    
    def __run_on_micro_httpd(self):
        """sscanf(&v37, "%[^ ] %[^ ] %[^ ]", &v40, &v41, &v44);
        """
        keyword = "%[^ ] %[^ ] %[^ ]"
        calls = get_call_ssa_instructions_to(self.__module, "sscanf")
        for call_insn in calls:
            params = call_insn.params
            if len(params) < 2:
                continue
            sscanf_str_insn : MediumLevelILInstruction = params[1]
            if sscanf_str_insn.operation not in (
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR
                ):
                continue
            addr = sscanf_str_insn.constant
            sscanf_str, _ = safe_str(self.__module, addr)
            if sscanf_str != keyword:
                continue
            if params[0].operation != MediumLevelILOperation.MLIL_VAR_SSA:
                continue
            ptr_to_buffer = params[0].src
            func : Function = call_insn.function.source_function
            dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(DominatorTreeAnalysis, func)
            equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(EquivalentAnalysis, func)
            found_fgets = False
            found_strstr = False
            for blk in func.mlil.ssa_form:
                if found_strstr and found_fgets:
                    break
                for insn in blk:
                    if insn.operation not in (
                        MediumLevelILOperation.MLIL_CALL_SSA,
                        MediumLevelILOperation.MLIL_TAILCALL_SSA
                        ):
                        continue
                    if insn == call_insn:
                        continue
                    if not dominator_tree_analysis.does_dominate(call_insn, insn):
                        continue
                    name = get_callee_name(self.__module, insn)
                    if found_fgets == False and name == "fgets" and len(insn.params) >= 3:
                        xaddr_insn : MediumLevelILInstruction = insn.params[0]
                        xlen_insn : MediumLevelILInstruction  = insn.params[1]
                        if xaddr_insn.operation != MediumLevelILOperation.MLIL_VAR_SSA or \
                            xlen_insn.operation not in (MediumLevelILOperation.MLIL_CONST_PTR, MediumLevelILOperation.MLIL_CONST):
                            continue
                        
                        if not equivalent_analysis.are_equivalent(ptr_to_buffer, xaddr_insn.src, insn):
                            continue
                        found_fgets = True
                    
                    if found_fgets and found_strstr == False and name == "strstr" and len(insn.params) >= 2:
                        src_insn   : MediumLevelILInstruction = insn.params[0]
                        const_insn : MediumLevelILInstruction = insn.params[1]
                        if src_insn.operation != MediumLevelILOperation.MLIL_VAR_SSA or \
                            const_insn.operation not in (MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR):
                            continue

                        const_value, _ = safe_str(self.__module, const_insn.constant)
                        if equivalent_analysis.are_equivalent(src_insn.src, ptr_to_buffer, insn) and \
                            const_value == "/../":
                            found_strstr = True
                    
            if found_strstr == False:
                self.report(UrlFilterIssue(func, "micro_httpd"))
                        
    def __run_on_general(self):
        pass