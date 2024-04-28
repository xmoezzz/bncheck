from analysis.basic import Module, ModuleAnalysis, ModuleAnalysisManager
from binaryninja import MediumLevelILOperation, MediumLevelILInstruction, Function

import typing

class CrossReferenceItem(object):
    def __init__(self, func : Function, insn : MediumLevelILInstruction):
        """被哪个函数所引用
           在这个函数内具体是被哪条指令给引用的
        
        Arguments:
            object {[type]} -- [description]
            func {Function} -- [description]
            insn {MediumLevelILInstruction} -- [description]
        """
        assert isinstance(func, Function)
        assert isinstance(insn, MediumLevelILInstruction)

        self.__func : Function = func
        self.__insn : MediumLevelILInstruction = insn
    
    @property
    def function(self) -> Function:
        return self.__func
    
    @property
    def insn(self) -> MediumLevelILInstruction:
        return self.__insn


class CallGraphAnalysis(ModuleAnalysis):
    """我们不能信任bn提供给我们的call graph
        (1)对于mips,xrefs可能定位到move t9, xxx上,而不是调用上,
          而move指令上的ir是空的
        (2)有的call graph不太对
    
    Arguments:
        ModuleAnalysis {[type]} -- [description]
    """
    def run_on_module(self, module:Module, mam: ModuleAnalysisManager):
        self.__cache : typing.Dict[Function, typing.List[CrossReferenceItem]] = dict()
        self.__module : Module = module
        assert isinstance(module, Module)
        for func in module.functions:
            for blk in func.mlil.ssa_form:
                for insn in blk:
                    if insn.operation in (
                        MediumLevelILOperation.MLIL_CALL_SSA,
                        MediumLevelILOperation.MLIL_TAILCALL_SSA
                        ):
                        self.__append_reference(func, insn)
    
    def __append_reference(self, func : Function, insn : MediumLevelILInstruction) -> bool:
        dest_insn : MediumLevelILInstruction = insn.dest
        if dest_insn.operation not in (
            MediumLevelILOperation.MLIL_CONST,
            MediumLevelILOperation.MLIL_CONST_PTR
            ):
            return False
        
        addr = dest_insn.constant
        target_func : Function = self.__module.get_function_at(addr)
        if target_func is None:
            return False
        
        r = CrossReferenceItem(func, insn)
        if target_func not in self.__cache:
            self.__cache[target_func] = list()
        self.__cache[target_func].append(r)
        return True
    
    def get_cross_reference_by(self, func : Function)->typing.List[CrossReferenceItem]:
        if func in self.__cache:
            return self.__cache[func]
        return []
        
        
        