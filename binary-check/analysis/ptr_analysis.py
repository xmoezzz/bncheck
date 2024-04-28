import binaryninja
import typing
import logging

from analysis.basic import ModuleAnalysisManager, Module, Function, \
    ModuleAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from binaryninja import MediumLevelILOperation, MediumLevelILInstruction
from utils.base_tool import get_callee_name

logger = logging.getLogger(__file__)


"""
a = &b	a⊇b  b∈pts(a)                 None
a = b   a⊇b  pts(a)⊃pts(b)            b→a
a = *b  a⊇∗b ∀v∈pts(b)|pts(a)⊃pts(v)  None
*a = b  ∗a⊇b ∀v∈pts(a)|pts(v)⊃pts(a)  None
"""

class PointerAnalysis(ModuleAnalysis):
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        #self.__equivalent_analysis : EquivalentAnalysis = mam.get_module_analysis()
        self.__ptr_size = self.__get_ptr_size()
        self.__interesting_funcs = {
            "malloc" : [(0, 1)],
            "relloc" : [(0, 0), (1, 1), (2, 1)],
            "calloc" : [(0, 1), (1, 1)]
        }
        
    def __get_ptr_size(self)->int:
        assert isinstance(self.__module, Module)
        if self.__module.arch.name in ("aarch64", "ppc64", "ppc64_le"):
            return 8
        if self.__module.arch.name in ("ppc", "ppc_le", "armv7", "armv7eb", "x86", "mipsel32", "mips32"):
            return 4
        if self.__module.arch.name in ("x86_16"):
            return 2
        assert NotImplementedError("Unsupported arch : %s" %  self.__module.arch.name)
    
    def __on_collect_ptrs(self):
        ptrs = {}
        for func in self.__module.functions:
            for blk in func.mlil.ssa_form:
                for insn in blk:
                    if insn.operation in (
                        MediumLevelILOperation.MLIL_STORE_SSA
                        ):
                        if insn.size == self.__ptr_size:
                            pass
                    
                    if insn.operation in (
                        MediumLevelILOperation.MLIL_SET_VAR_SSA
                        ):
                        if insn.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                            pass
                        elif insn.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                            pass
                    
                    if insn.operation in (
                        MediumLevelILOperation.MLIL_CALL_SSA,
                        MediumLevelILOperation.MLIL_TAILCALL_SSA
                        ):
                        callee_name = get_callee_name(self.__module, insn)
                        if callee_name in self.__interesting_funcs:
                            pass
                        
