from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.module_info_analysis import ModuleInfoAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.value_set_analysis import SimpleValueSetAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.return_var_analysis import ReturnVarAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.checkers.crypto_base.basic import CryptoReportItemBase, CallChainItem
from analysis.call_to_func_analysis import CallToFuncAnalysis, CallToFuncCallChain, \
    CallToFuncItem, CallToFuncList

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation, \
    SSAVariable, Variable, Type
from utils.base_tool import safe_str, get_callee_name

import binaryninja
import typing
import logging
import copy
import pprint

logger = logging.getLogger(__name__)


class CryptoEcbModeReportItem(CryptoReportItemBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        chain = copy.copy(self.chain)
        chain.reverse()
        rp = "%s : ecb mode\n" % (self.desc)
        for item in chain:
            desc = '-----------------\nfunc : %s\ninstruction : %s\ntarget index : %d\n-----------------\n' % (
                item.func,
                item.insn,
                item.target_index
            )
            rp += desc
        
        rp += '\n\n'
        return rp


class CryptoEcbModeChecker(CheckerBase):
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
        return "CryptoEcbMode"

    def __validate_parameter(self, params : typing.List[MediumLevelILInstruction], index : int, const_value : int)->bool:
        param_insn : MediumLevelILInstruction = params[index]
        if param_insn.operation == MediumLevelILOperation.MLIL_CONST and param_insn.constant == const_value:
            return True
        return False

    def __check_set_xxx_ecb(
        self, 
        call_to_func_analysis : CallToFuncAnalysis, 
        function_name : str, 
        param_index : int, 
        const_value : int, 
        tag : str):

        results : CallToFuncList = call_to_func_analysis.get_call_to_func(function_name, param_index)
        if len(results) == 0:
            return
        
        for chain in results:
            #wtf?
            assert len(chain) != 0
            issue = CryptoEcbModeReportItem()
            for item in chain:
                issue.push(item.owner, item.instruction, item.target_index)
            last_item = chain[-1]
            if self.__validate_parameter(last_item.instruction.params, last_item.target_index, const_value):
                issue.set_desc(tag)
                self.report(issue)
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        """我们是否需要依赖version-scan的数据
        """

        """libgcrypto
        """
        call_to_func_analysis : CallToFuncAnalysis = mam.get_module_analysis(CallToFuncAnalysis, module)
        self.__check_set_xxx_ecb(call_to_func_analysis, "gcry_cipher_open", 2, 1, "libgcrypto : gcry_cipher_open")

        """mbedtls
        """
        calls = get_call_ssa_instructions_to(module, "mbedtls_aes_crypt_ecb")
        for call_insn in calls:
            func : Function = call_insn.function.source_function
            issue = CryptoEcbModeReportItem()
            issue.set_desc("mbedtls : mbedtls_aes_crypt_ecb")
            self.report(issue)

    
