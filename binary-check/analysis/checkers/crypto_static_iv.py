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

logger = logging.getLogger(__name__)

class CryptoStaticIVReportItem(CryptoReportItemBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.iv : str = None
        self.iv_address : int = None
    
    def set_iv(self, iv : str):
        if not self.iv is None:
            logger.warning("iv was reset")
        self.iv = iv
    
    def set_iv_address(self, iv_address : int):
        if not self.iv_address is None:
            logger.warning("iv address was reset")
        self.iv_address = iv_address
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        chain = copy.copy(self.chain)
        chain.reverse()
        rp = "%s : static iv (%s)(%x)\n" % (self.desc, self.iv, self.iv_address)
        for item in chain:
            desc = '-----------------\nfunc : %s\ninstruction : %s\ntarget index : %d\n-----------------\n' % (
                item.func,
                item.insn,
                item.target_index
            )
            rp += desc
        
        rp += '\n\n'
        return rp


class CryptoStaticIVChecker(CheckerBase):
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
        return "CryptoStaticIV"

    def __validate_parameter(self, params : typing.List[MediumLevelILInstruction], index : int)->typing.Union[bool, int, str]:
        param_insn : MediumLevelILInstruction = params[index]
        if param_insn.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            addr = param_insn.constant
            static_value, _ = safe_str(self.__module, addr)
            return True, addr, static_value
        return False, -1, None

    def __check_set_xxx_iv(self, call_to_func_analysis : CallToFuncAnalysis, function_name : str, param_index : int, tag : str):
        results : CallToFuncList = call_to_func_analysis.get_call_to_func(function_name, param_index)
        if len(results) == 0:
            return
        
        for chain in results:
            #wtf?
            assert len(chain) != 0
            issue = CryptoStaticIVReportItem()
            for item in chain:
                issue.push(item.owner, item.instruction, item.target_index)
            last_item = chain[-1]
            state, addr, static_iv = self.__validate_parameter(last_item.instruction.params, last_item.target_index)
            if state:
                issue.set_desc(tag)
                issue.set_iv_address(addr)
                issue.set_iv(static_iv)
                self.report(issue)
        
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        """我们是否需要依赖version-scan的数据
        """

        call_to_func_analysis : CallToFuncAnalysis = mam.get_module_analysis(CallToFuncAnalysis, module)

        """wolfcrypt
        """
        self.__check_set_xxx_iv(call_to_func_analysis, "wc_AesSetIv", 1, "wolfcrypt : wc_AesSetIv")

        """tiny-AES-c
        """
        self.__check_set_xxx_iv(call_to_func_analysis, "AES_init_ctx_iv", 2, "tiny-AES-c : AES_init_ctx_iv")
        self.__check_set_xxx_iv(call_to_func_analysis, "AES_ctx_set_iv",  1, "tiny-AES-c : AES_ctx_set_iv")
        
        """libtomcrypt
        """

        """int ctr_start(               int   cipher,
              const unsigned char *IV,
              const unsigned char *key,       int keylen,
                             int  num_rounds, int ctr_mode,
                   symmetric_CTR *ctr);
        """
        self.__check_set_xxx_iv(call_to_func_analysis, "ctr_start", 1, "libtomcrypt : ctr_start")

        """crypto-algorithms
        """
        
        """void increment_iv(BYTE iv[],                  // Must be a multiple of AES_BLOCK_SIZE
                  int counter_size);          // Bytes of the IV used for counting (low end)
        """
        self.__check_set_xxx_iv(call_to_func_analysis, "increment_iv", 1, "crypto-algorithms : increment_iv")

        
    
