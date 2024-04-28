from analysis.basic import ModuleAnalysisManager, Module, ModuleAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.value_set_analysis import StandardSSAVariable
from analysis.dominator_tree import DominatorTreeAnalysis

from binaryninja import Function, MediumLevelILInstruction, MediumLevelILOperation, \
    SSAVariable

import logging
import typing
import enum 
import copy
from socket_prototype.read import ReadPrototype
from socket_prototype.write import WritePrototype
from socket_prototype.socket_prototype import SocketParamType, SocketPrototype
from utils.base_tool import get_callee_name



class SocketCtrlType(enum.IntEnum):
    SOCKET_READ = 0
    SOCKET_WRITE = 1


class SocketCtrlItem(object):
    def __init__(self, func : Function, ir : MediumLevelILInstruction, fd : StandardSSAVariable, proc : Function):
        self.__func = func
        self.__ir = ir
        self.__fd = fd
        """可能是None
        """
        self.__proc = proc
        self.__call_proc_insn = None
        self.__type = None
    
    def update_proc(self, proc : Function):
        assert isinstance(proc, Function)
        self.__proc = proc
    
    def update_call_proc_insn(self, insn : MediumLevelILInstruction):
        assert isinstance(insn, MediumLevelILInstruction)
        self.__call_proc_insn = insn
    
    def update_type(self, t : SocketCtrlType):
        assert isinstance(t, SocketCtrlType)
        self.__type = t
    
    @property
    def proc_type(self)->SocketCtrlType:
        return self.__type

    @property
    def call_proc_insn(self)->MediumLevelILInstruction:
        return self.__call_proc_insn
        
    @property
    def function(self)->Function:
        return self.__func
    
    @property
    def insn(self)->MediumLevelILInstruction:
        return self.__ir
    
    @property
    def file_descriptor(self):
        return self.__fd
    
    @property
    def proc(self)->Function:
        return self.__proc
    
    def fork(self):
        child = SocketCtrlItem(self.__func, self.__ir, self.__fd, self.__proc)
        if not self.__call_proc_insn is None:
            child.update_call_proc_insn(self.__call_proc_insn)
        if not self.__type is None:
            child.update_type(self.__type)
        return child


class SocketCtrlAnalysis(ModuleAnalysis):
    """socket读取写入
       在哪个函数，在哪个IR上被使用
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__max_call_depth = 5
        self.__call_depth = self.__max_call_depth
        if "call_depth" in kwargs:
            self.__call_depth = kwargs["call_depth"]
        if self.__call_depth > self.__max_call_depth:
            self.__call_depth = self.__max_call_depth
        if self.__call_depth < 0:
            self.__call_depth = self.__max_call_depth
        
    
    def run_on_module(self, module:Module, mam: ModuleAnalysisManager):
        self.__items : typing.List[SocketCtrlItem] = list()
        self.__module : Module =  module
        self.__mam : ModuleAnalysisManager = mam
        calls = get_call_ssa_instructions_to(module, 'socket')
        for call_insn in calls:
            outputs = call_insn.output.dest
            if len(outputs) < 1:
                continue
            fd = outputs[0]
            is_ssa : bool = isinstance(fd, SSAVariable)
            func : Function = call_insn.function.source_function
            item = SocketCtrlItem(func, call_insn, fd, None)
            self.__on_collect_function(item, call_insn, set(fd), 0)
    
    def get_items(self)->typing.List[SocketCtrlItem]:
        return self.__items
            
    
    def __on_collect_function(self, item : SocketCtrlItem, insn : MediumLevelILInstruction, fd_set : typing.Set[SSAVariable], depth : int):
        func : Function = insn.function.source_function
        dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(func, DominatorTreeAnalysis)
        equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(func, EquivalentAnalysis)
        
        for blk in func:
            for inst in blk:
                if inst.operation not in (
                    MediumLevelILOperation.MLIL_CALL_SSA,
                    MediumLevelILOperation.MLIL_TAILCALL_SSA
                    ):
                    continue

                """我们已经进入后续迭代
                   这里的insn代表是函数的开始点，所有的ir都应该支配
                """
                if insn is not None:
                    if insn == inst:
                        continue
                    if not dominator_tree_analysis.does_dominate(insn, inst):
                        continue
                name = get_callee_name(self.__module, inst)
                pp = None
                cc_ctrl = None
                if name in ReadPrototype:
                    pp = SocketPrototype(ReadPrototype[name], name)
                    cc_ctrl = SocketCtrlType.SOCKET_READ
                if name in WritePrototype:
                    pp = SocketPrototype(WritePrototype[name], name)
                    cc_ctrl = SocketCtrlType.SOCKET_WRITE
                
                def are_equivalent(variable : SSAVariable, current_insn : MediumLevelILInstruction):
                    for fd in fd_set:
                        if equivalent_analysis.are_equivalent(variable, fd, current_insn):
                            return True
                    return False
                
                if pp != None:
                    params = pp.params
                    maxsize = min(len(params), len(inst.params))
                    for i in range(maxsize):
                        p = inst.params[i]
                        t = params[i]
                        if t == SocketParamType.SOCKET_FD and p.operation == MediumLevelILOperation.MLIL_VAR_SSA and are_equivalent(p.src, inst):
                            child : SocketCtrlItem = item.fork()
                            addr = inst.dest.constant
                            f = self.__module.get_function_at(addr)
                            child.update_proc(f)
                            child.update_call_proc_insn(inst)
                            self.__items.append(child)
                else:
                    if depth >= self.__call_depth:
                        continue
                    if inst.dest.operation not in (
                        MediumLevelILOperation.MLIL_CALL_SSA,
                        MediumLevelILOperation.MLIL_TAILCALL_SSA
                        ):
                        continue
                    equivalent_param = None
                    for p in inst.params:
                        if p.operation != MediumLevelILOperation.MLIL_VAR_SSA:
                            continue
                        """如果我们有两个或者以上的参数与fd等价呢
                        """

                        if are_equivalent(p.src, inst):
                            equivalent_param = p.src
                            break
                    
                    if equivalent_param is None:
                        continue
                    child = item.fork()
                    child_insn = insn
                    if insn != None:
                        child_insn = None
                    self.__on_collect_function(child, child_insn, equivalent_param, depth + 1)
                
