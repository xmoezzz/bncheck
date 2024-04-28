from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.module_info_analysis import ModuleInfoAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.value_set_analysis import SimpleValueSetAnalysis
from analysis.return_var_analysis import ReturnVarAnalysis
from analysis.call_to_func_analysis import CallToFuncAnalysis, CallToFuncCallChain, \
    CallToFuncItem, CallToFuncList
from analysis.utils import get_call_ssa_instructions_to
from analysis.checkers.crypto_base.basic import CryptoReportItemBase, CallChainItem

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation, \
    SSAVariable, Variable, Type
from utils.base_tool import safe_str, get_callee_name

import binaryninja
import typing
import logging
import enum
import copy

logger = logging.getLogger(__name__)

class SrandStaticSeedreportItem(CryptoReportItemBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        chain = copy.copy(self.chain)
        chain.reverse()
        rp = "%s : static seed\n" % (self.desc)
        for item in chain:
            desc = '-----------------\nfunc : %s\ninstruction : %s\ntarget index : %d\n-----------------\n' % (
                item.func,
                item.insn,
                item.target_index
            )
            rp += desc
        
        rp += '\n\n'
        return rp

class SrandStaticSeedChecker(CheckerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__max_depth = 3
        self.__depth = 3
        if 'depth' in kwargs:
            depth = kwargs['depth']
            assert isinstance(depth, int)
            self.__depth = depth
        if self.__depth > self.__max_depth:
            logger.warning('depth is too large')
            self.__depth = self.__max_depth
        if self.__depth < 0:
            logger.warning('depth is too small')
            self.__depth = self.__max_depth
    
    @staticmethod
    def get_checker_name()->str:
        return "SrandStaticSeed"
    
    def __validate_srand_parameter(self, params : typing.List[MediumLevelILInstruction], index : int)->bool:
        param_insn : MediumLevelILInstruction = params[index]
        if param_insn.operation in (MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR):
            return True
        return False

    def __on_check_xxx_static_seed(self, call_to_func_analysis : CallToFuncAnalysis, func_name : str, param_insn : int, tag :str):
        results : CallToFuncList = call_to_func_analysis.get_call_to_func(func_name, param_insn)
        if len(results) == 0:
            return
        
        for chain in results:
            #wtf?
            assert len(chain) != 0
            issue = SrandStaticSeedreportItem()
            issue.set_desc(tag)
            for item in chain:
                issue.push(item.owner, item.instruction, item.target_index)
            last_item = chain[-1]
            if self.__validate_srand_parameter(last_item.instruction.params, last_item.target_index):
                self.report(issue)
            
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        _call_to_func_analysis : CallToFuncAnalysis = self.__mam.get_module_analysis(CallToFuncAnalysis, module)

        """libc
        """
        self.__on_check_xxx_static_seed(_call_to_func_analysis, "srand", 0, "libc : srand")

        """mt19937
        """
        
        """void init_genrand(unsigned long s);
        """
        self.__on_check_xxx_static_seed(_call_to_func_analysis, "init_genrand", 0, "mt19937 : init_genrand")

        """void init_by_array(unsigned long init_key[], int key_length);
        """
        self.__on_check_xxx_static_seed(_call_to_func_analysis, "init_by_array", 0, "mt19937 : init_by_array")


        