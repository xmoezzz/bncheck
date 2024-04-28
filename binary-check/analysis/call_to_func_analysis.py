from analysis.basic import FunctionAnalysis, AnalysisManager, Module, Function, ModuleAnalysisManager, ModuleAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.checkers.cpu64.cpu64_equivalent_analysis import Cpu64EquivalentAnalysis

from binaryninja import Function, MediumLevelILInstruction, MediumLevelILOperation, \
    SSAVariable, Variable

import typing
import copy

class CallToFuncKey(object):
    def __init__(self, module : Module,  depth : int, address_or_function : typing.Union[int, str]):
        if not isinstance(address_or_function, int) or not isinstance(address_or_function, str):
            raise TypeError("wrong type for address_or_function : %s" % (type(address_or_function)))
        self.address_name = None
        self.depth = depth
        if isinstance(address_or_function, str):
            self.address_name = address_or_function
        else:
            func : Function = module.get_function_at(address_or_function)
            if func is None:
                raise RuntimeError("no function at %s" % (hex(address_or_function)))
            self.address_name = func.start
    
    def __hash__(self):
        return hash(self.depth, self.address_name)

class ParameterStorage(object):
    def __init__(self, idx : int, ssa_var : SSAVariable):
        """[summary]
        
        Arguments:
            object {[type]} -- [description]
            idx {int} -- 从0开始
            ssa_var {SSAVariable} -- [description]
        """
        self.__idx : int= idx
        self.__ssa_var : SSAVariable = ssa_var
    
    @property
    def index(self)->int:
        return self.__idx
    
    @property
    def storage(self)->SSAVariable:
        return self.__ssa_var

class CallToFuncItem(object):
    def __init__(
        self, 
        owner : Function, 
        equivalent_parameter : ParameterStorage,
        insn : MediumLevelILInstruction,
        target_index : int
        ):
        """[summary]
        
        Arguments:
            owner {Function} -- 指令所属的函数
            equivalent_parameters {typing.List[ParameterStorage]} -- 本函数形参中和目标指令参数等价的列表
            insn {MediumLevelILInstruction} -- 目标的call指令
        """
        self.__owner : Function = owner
        self.__equivalent_parameter : ParameterStorage = equivalent_parameter
        self.__insn : MediumLevelILInstruction = insn
        self.__target_index : int = target_index
    
    @property
    def owner(self)->Function:
        return self.__owner
    
    @property
    def equivalent_parameters(self)->ParameterStorage:
        return self.__equivalent_parameter
    
    @property
    def instruction(self)->MediumLevelILInstruction:
        return self.__insn
    
    @property
    def target_index(self)->int:
        return self.__target_index


class CallToFuncCallChain(list):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def fork(self):
        child = copy.copy(self)
        return child
    
class CallToFuncList(list):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class CallToFuncAnalysis(ModuleAnalysis):
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        self.__max_depth = 3
    
    def __equal_to_any_parameters(
        self, 
        func : Function, 
        ssa_var : SSAVariable, 
        insn : MediumLevelILInstruction) -> typing.Tuple[bool, int]:
        """[summary]
        
        Arguments:
            func {Function} -- the owner
            ssa_var {SSAVariable} -- ssa var
            insn {MediumLevelILInstruction} -- at which instruction
        
        Returns:
        """
        equivalent_analysis : Cpu64EquivalentAnalysis = self.__mam.get_function_analysis(Cpu64EquivalentAnalysis, func)
        for idx, v in enumerate(func.parameter_vars.vars):
            svar = SSAVariable(v, 0)
            if equivalent_analysis.are_equivalent(svar, ssa_var, insn):
                return True, idx
            
        return False, -1
    
    def get_call_to_func(
        self,
        address_or_name : typing.Union[int, str],
        index : int,
        depth : int = 3)->CallToFuncList:
        """[summary]
        
        Arguments:
            address_or_name {typing.Union[int, str]} -- [description]
            index {int} -- index
            depth {int} -- [description]
        
        Returns:
            CallToFuncList -- [description]
        """
        if depth > self.__max_depth:
            depth == self.__max_depth
        if depth < 0:
            depth = 0
        
        call_list = CallToFuncList()
        calls = get_call_ssa_instructions_to(self.__module, address_or_name)
        for call_insn in calls:
            func : Function = call_insn.function.source_function
            params : typing.List[MediumLevelILInstruction] = call_insn.params
            if len(params) <= index:
                continue

            param_insn : MediumLevelILInstruction = params[index]
            if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and depth != 0:
                state, idx = self.__equal_to_any_parameters(func, param_insn.src, call_insn)
                if state:
                    s = ParameterStorage(idx, SSAVariable(func.parameter_vars.vars[idx], 0))
                    item = CallToFuncItem(func, s, call_insn, idx)
                    chain = CallToFuncCallChain()
                    chain.append(item)
                    next_calls = get_call_ssa_instructions_to(self.__module, func.start)
                    if next_calls is None or len(next_calls) == 0:
                        continue
                    for next_call_insn in next_calls:
                        next_func : Function = next_call_insn.function.source_function
                        self.__on_check_next(call_list, chain, depth, next_func, next_call_insn, idx, 0)

                    
            elif param_insn.operation in (
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR
                ):
                item = CallToFuncItem(func, None, call_insn, index)
                chain = CallToFuncCallChain()
                chain.append(item)
                call_list.append(chain)
        
        return call_list

    def __on_check_next(
        self, 
        results : CallToFuncList, 
        chain : CallToFuncCallChain, 
        max_depth : int, 
        func : Function, 
        insn : MediumLevelILInstruction, 
        index : int, 
        depth : int):

        if depth >= max_depth:
            return
        
        params : typing.List[MediumLevelILInstruction] = insn.params
        if len(params) < index:
            return
        param_insn : MediumLevelILInstruction = params[index]
        if param_insn.operation in (
            MediumLevelILOperation.MLIL_CONST,
            MediumLevelILOperation.MLIL_CONST_PTR):
            s = CallToFuncItem(func, None, insn, index)
            chain.append(s)
            results.append(chain)
        if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            next_calls = get_call_ssa_instructions_to(self.__module, func.start)
            if next_calls is None or len(next_calls) == 0:
                return
            state, next_index = self.__equal_to_any_parameters(func, param_insn.src, insn)
            if not state:
                return
            for next_call_insn in next_calls:
                next_func : Function = next_call_insn.function.source_function
                self.__on_check_next(results, chain.fork(), max_depth, next_func, next_call_insn, next_index, depth + 1)
                
                    