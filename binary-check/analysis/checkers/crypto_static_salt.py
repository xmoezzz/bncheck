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

class CryptoStaticSaltReportItem(CryptoReportItemBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.salt : str = None
        self.salt_address : int = None
    
    def set_salt(self, salt : str):
        if not self.salt is None:
            logger.warning("salt was reset")
        self.salt = salt
    
    def set_salt_address(self, salt_address : int):
        if not self.salt_address is None:
            logger.warning("salt address was reset")
        self.salt_address = salt_address
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        chain = copy.copy(self.chain)
        chain.reverse()
        rp = "%s : static salt (%s)(%x)\n" % (self.desc, self.salt, self.salt_address)
        for item in chain:
            desc = '-----------------\nfunc : %s\ninstruction : %s\ntarget index : %d\n-----------------\n' % (
                item.func,
                item.insn,
                item.target_index
            )
            rp += desc
        
        rp += '\n\n'
        return rp

class CryptoStaticSaltChecker(CheckerBase):
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
        return "CryptoStaticSalt"
    
    def __validate_parameter(self, params : typing.List[MediumLevelILInstruction], index : int)->typing.Union[bool, int, str]:
        param_insn : MediumLevelILInstruction = params[index]
        if param_insn.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            addr = param_insn.constant
            static_value, _ = safe_str(self.__module, addr)
            return True, addr, static_value
        return False, -1, None

    def __check_set_xxx_salt(self, call_to_func_analysis : CallToFuncAnalysis, function_name : str, param_index : int, tag : str):
        results : CallToFuncList = call_to_func_analysis.get_call_to_func(function_name, param_index)
        if len(results) == 0:
            return
        
        for chain in results:
            #wtf?
            assert len(chain) != 0
            issue = CryptoStaticSaltReportItem()
            for item in chain:
                issue.push(item.owner, item.instruction, item.target_index)
            last_item = chain[-1]
            state, addr, static_value = self.__validate_parameter(last_item.instruction.params, last_item.index)
            if state:
                issue.set_desc(tag)
                issue.set_salt_address(addr)
                issue.set_salt(static_value)
                self.report(issue)
    

    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        """我们是否需要依赖version-scan的数据
        """

        call_to_func_analysis : CallToFuncAnalysis = mam.get_module_analysis(CallToFuncAnalysis, module)
        self.__check_set_xxx_salt(call_to_func_analysis, "crypt", 1, "libc : crypt")
        

