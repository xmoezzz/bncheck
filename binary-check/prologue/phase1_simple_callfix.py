import binaryninja
import typing
import logging

from prologue.basic import PrologueAnalysis, Module
from analysis.basic import ModuleAnalysisManager
from function_filters.sources import SourceTarget
from function_filters.targets import DestTarget
from function_filters.transfers import TaintSource
from function_filters.basic import init_with_chunk_dict, FunctionType
from analysis.utils import get_call_ssa_instructions_to
from binaryninja import MediumLevelILOperation, MediumLevelILInstruction, Function, \
    SSAVariable, Variable, VariableSourceType, RegisterValueType
from utils.base_tool import safe_str, calc_format_string


logger = logging.getLogger(__file__)

class SimpleCallfixAnalysis(PrologueAnalysis):
    """SimpleCallfixAnalysis只会去修复类似printf的参数不太对的调用
       因为bn不支持IR变参，所以只能根据最大值的来修正函数原型
       在taint的时候，我们需要根据format string来确定真正的参数个数
    
    Arguments:
        PrologueAnalysis {[type]} -- [description]
    """
    def on_load(self, module:Module, mam:ModuleAnalysisManager):
        self.__caches = {}
        self.__module = module
        self.__require_restart = False

        known_prototypes = []
        for src in init_with_chunk_dict(SourceTarget):
            known_prototypes.append(src)
        
        for src in init_with_chunk_dict(DestTarget):
            known_prototypes.append(src)
        
        for src in init_with_chunk_dict(TaintSource):
            known_prototypes.append(src)
        
        for known_prototype in known_prototypes:
            ssa_calls = get_call_ssa_instructions_to(module, known_prototype.name)
            for ssa_call in ssa_calls:
                func : Function = self.get_callee_function(ssa_call)
                if func is None:
                    continue
                func = self.refetch_function(func)
                if known_prototype.func_type != FunctionType.FUNC_STR_VARARG:
                    continue

                count : int = known_prototype.count
                fstr_index : int = known_prototype.fstr_index
                old_parameter_count : int = len(func.parameter_vars)
                params : typing.List[SSAVariable] = ssa_call.params
                if len(params) <= known_prototype.var_index:
                    fixed_count = self.__on_fix_normal_parameters(func, known_prototype.var_index)
                    if fixed_count != known_prototype.var_index:
                        logger.warning('fix failed')
                        continue
                
                assert known_prototype.var_index >= fstr_index
                
                fstr : MediumLevelILInstruction = params[fstr_index]
                if fstr.operation in (
                    MediumLevelILOperation.MLIL_CONST,
                    MediumLevelILOperation.MLIL_CONST_PTR
                    ):
                    fstr_val, _ = safe_str(module, fstr.constant)
                    vararg_size = calc_format_string(fstr_val)
                    new_size = known_prototype.var_index + vararg_size
                    if old_parameter_count >= new_size:
                        continue

                    fixed_size = self.__on_fix(func, new_size)
                    if fixed_size != new_size:
                        logger.debug('failed to fix : %s' % str(ssa_call))
                    else:
                        self.__require_restart = True
                
                elif fstr.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                    if fstr.possible_values.type != RegisterValueType.InSetOfValues:
                        continue
                    max_vararg_count = 0
                    for value in fstr.possible_values.values:
                        fstr_val, _ = safe_str(module, value)
                        if fstr_val is None:
                            continue

                        vararg_size = calc_format_string(fstr_val)
                        max_vararg_count = max(max_vararg_count, vararg_size)
                    
                    func = self.refetch_function(func)
                    old_parameter_count = len(func.parameter_vars)
                    
                    new_size = known_prototype.var_index + max_vararg_count + 1
                    if old_parameter_count >= new_size:
                        continue

                    fixed_size = self.__on_fix(func, new_size)
                    if fixed_size != new_size:
                        logger.debug('failed to fix : %s' % str(ssa_call))
                    else:
                        self.__require_restart = True
                    
    
    def refetch_function(self, old_func : Function)->Function:
        """当前的函数需要重新获得,要不然后续的修改无效
        
        Arguments:
            old_func {Function} -- [description]
        
        Returns:
            Function -- [description]
        """
        assert isinstance(old_func, Function)
        new_func : Function = self.__module.get_function_at(old_func.start)
        assert isinstance(new_func, Function)
        return new_func

    
    def require_restart(self) -> bool:
        return self.__require_restart
    
    def __on_fix_normal_parameters(self, func : Function, desired_count : int) -> int:
        return self.__on_fix(func, desired_count)
    
    def get_callee_function(self, insn : MediumLevelILInstruction) -> typing.Union[None, Function]:
        if insn.operation in (MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA):
            dest_insn : MediumLevelILInstruction = insn.dest
            if dest_insn.operation not in (MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR):
                return None
            const_addr = dest_insn.constant
            return self.__module.get_function_at(const_addr)
        
        return None
    
    def __performce_fix_on_arm(self, func : Function, desired_count : int) -> int:
        armStackStart = 0
        armRegisterStart = 0
        armRegisterCount = 4

        index = 0
        for v in func.parameter_vars:
            index   = v.index
        
        varlist = []
        currentStack    = armStackStart
        currentRegister = armRegisterStart
        for i in range(desired_count):
            if i < armRegisterCount:
                v = Variable(func, VariableSourceType.RegisterVariableSourceType, index, currentRegister)
                varlist.append(v)
                currentRegister += 1
            else:
                v = Variable(func, VariableSourceType.StackVariableSourceType, index, currentStack)
                varlist.append(v)
                currentStack += 4
        
        func.parameter_vars = varlist
        self.__module.update_analysis_and_wait()
        return len(varlist)

    def __performce_fix_on_mips(self, func : Function, desired_count : int) -> int:
        mipsStackStart = 16
        mipsRegisterStart = 4
        mipsRegisterCount = 4

        index = 0
        for v in func.parameter_vars:
            index   = v.index
        
        varlist = []
        currentStack    = mipsStackStart
        currentRegister = mipsRegisterStart
        for i in range(desired_count):
            if i < mipsRegisterCount:
                v = Variable(func, VariableSourceType.RegisterVariableSourceType, index, currentRegister)
                varlist.append(v)
                currentRegister += 1
            else:
                v = Variable(func, VariableSourceType.StackVariableSourceType, index, currentStack)
                varlist.append(v)
                currentStack += 4
        
        func.parameter_vars = varlist
        self.__module.update_analysis_and_wait()
        return len(varlist)

    def __performce_fix_on_ppc(self, func : Function, desired_count : int) -> int:
        """fix ppc
           并没有任何文档
           如何确认这些index的在下次更新中的准确性?
        
        Arguments:
            func {Function} -- [description]
            desired_count {int} -- [description]
        
        Returns:
            int -- [description]
        """
        ppcStackStart = 0
        ppcRegisterStart = 48
        ppcRegisterCount = 8

        index = 0
        for v in func.parameter_vars:
            index   = v.index
        
        varlist = []
        currentStack    = ppcStackStart
        currentRegister = ppcRegisterStart
        for i in range(desired_count):
            if i < ppcRegisterCount:
                v = Variable(func, VariableSourceType.RegisterVariableSourceType, index, currentRegister)
                varlist.append(v)
                currentRegister += 1
            else:
                v = Variable(func, VariableSourceType.StackVariableSourceType, index, currentStack)
                varlist.append(v)
                currentStack += 4
        
        func.parameter_vars = varlist
        self.__module.update_analysis_and_wait()
        return len(varlist)
    
 
    def __performce_fix_on_x86(self, func : Function, desired_count : int) -> int:
        """CICS 就不修了
           撤回前言，x86-32可能还是需要修的
        
        Arguments:
            func {Function} -- [description]
            desired_count {int} -- [description]
        
        Returns:
            int -- [description]
        """
        return len(func.parameter_vars)

    def __performce_fix_on_amd64(self, func : Function, desired_count : int) -> int:
        return len(func.parameter_vars)

    def __performce_fix_on_aarch64(self, func : Function, desired_count : int) -> int:
        arm64StackStart = 0
        arm64RegisterStart = 34
        arm64RegisterCount = 8

        index = 0
        for v in func.parameter_vars:
            index   = v.index
        
        varlist = []
        currentStack    = arm64StackStart
        currentRegister = arm64RegisterStart
        for i in range(desired_count):
            if i < arm64RegisterCount:
                v = Variable(func, VariableSourceType.RegisterVariableSourceType, index, currentRegister)
                varlist.append(v)
                currentRegister += 1
            else:
                v = Variable(func, VariableSourceType.StackVariableSourceType, index, currentStack)
                varlist.append(v)
                currentStack += 8
        
        func.parameter_vars = varlist
        self.__module.update_analysis_and_wait()
        return len(func.parameter_vars)

    
    def __on_fix(self, func : Function, desired_count : int) -> int:
        assert isinstance(func, Function)
        assert isinstance(desired_count, int)

        arch : str = self.__module.arch.name
        if arch in ('armv7eb', 'armv7'):
            return self.__performce_fix_on_arm(func, desired_count)
        elif arch in ('mips32', 'mipsel32'):
            return self.__performce_fix_on_mips(func, desired_count)
        elif arch in ('powerpc', 'ppc'):
            return self.__performce_fix_on_ppc(func, desired_count)
        elif arch == 'x86':
            return self.__performce_fix_on_x86(func, desired_count)
        elif arch == 'x86_64':
            return self.__performce_fix_on_x86(func, desired_count)
        elif arch == 'aarch64':
            return self.__performce_fix_on_aarch64(func, desired_count)
        raise RuntimeError('unsupported arch : %s' % arch)


    