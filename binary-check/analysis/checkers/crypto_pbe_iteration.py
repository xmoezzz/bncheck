"""Do not use fewer than 1000 iterations for PBE
"""

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


class CryptoPBEFewerThan1000IterationsReportItem(CryptoReportItemBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.iteration = None
    
    def set_iteration(self, value : int):
        self.iteration = value
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        chain = copy.copy(self.chain)
        chain.reverse()
        rp = "%s : (%d)\n" % (self.desc, self.iteration)
        for item in chain:
            desc = '-----------------\nfunc : %s\ninstruction : %s\ntarget index : %d\n-----------------\n' % (
                item.func,
                item.insn,
                item.target_index
            )
            rp += desc
        
        rp += '\n\n'
        return rp

class CryptoPBEFewerThan1000IterationsChecker(CheckerBase):
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
        return "CryptoPBEFewerThan1000Iterations"
    
    def __on_search_target(self, value_set : typing.List[int])->bool:
        m = len(value_set) / 2
        if m == 0:
            return False
        if value_set[m] > 1000:
            return self.__on_search_target(value_set[:m])
        elif value_set[m] < 1000:
            return True
        elif value_set[m] == 1000:
            pass
        return False
    
    def __validate_parameter(self, params : typing.List[MediumLevelILInstruction], index : int)->typing.Union[bool, int]:
        param_insn : MediumLevelILInstruction = params[index]
        if param_insn.operation == MediumLevelILOperation.MLIL_CONST and param_insn.constant < 1000:
            value = param_insn.constant
            return True, value
        return False, None

    def __check_set_xxx_pbe(self, call_to_func_analysis : CallToFuncAnalysis, function_name : str, param_index : int, tag : str):
        results : CallToFuncList = call_to_func_analysis.get_call_to_func(function_name, param_index)
        if len(results) == 0:
            return
        
        for chain in results:
            #wtf?
            assert len(chain) != 0
            issue = CryptoPBEFewerThan1000IterationsReportItem()
            for item in chain:
                issue.push(item.owner, item.instruction, item.target_index)
            last_item = chain[-1]
            state, static_value = self.__validate_parameter(last_item.instruction.params, last_item.target_index)
            if state:
                issue.set_desc(tag)
                issue.set_iteration(static_value)
                self.report(issue)

    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        """我们是否需要依赖version-scan的数据
        """

        """不准确,因为范围可能是0-0xffffffff导致误报
        """
        """
        func : Function = mode_insn.function.source_function
        _value_set_analysis : SimpleValueSetAnalysis = self.__mam.get_function_analysis(SimpleValueSetAnalysis, func)
        #binary search?
        value_set = list(_value_set_analysis.get_state_of(mode_insn.src))
        if self.__on_search_target(value_set):
            rp = CryptoPBEFewerThan1000IterationsReportItem("libcrypto : EVP_BytesToKey")
            rp.push(func, call_insn)
            self.report(rp)
        """

        """int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                          const unsigned char *salt,
                          const unsigned char *data, int datal, int count,
                          unsigned char *key, unsigned char *iv);
        """
        
        call_to_func_analysis : CallToFuncAnalysis = mam.get_module_analysis(CallToFuncAnalysis, module)
        
        """libcrypto
        """
        self.__check_set_xxx_pbe(call_to_func_analysis, "EVP_BytesToKey", 5, "libcrypto : EVP_BytesToKey")
                    

    
