from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.module_info_analysis import ModuleInfoAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.value_set_analysis import SimpleValueSetAnalysis
from analysis.checkers.cpu64.cpu64_equivalent_analysis import Cpu64EquivalentAnalysis as EquivalentAnalysis
from analysis.return_var_analysis import ReturnVarAnalysis
from analysis.utils import get_call_ssa_instructions_to

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation, \
    SSAVariable, Variable, Type
from utils.base_tool import safe_str, get_callee_name

import binaryninja
import typing
import logging
import enum

logger = logging.getLogger(__name__)

class SignedOpType(enum.IntEnum):
    OP_MUL = 0,
    OP_ADD = 1,
    OP_SUB = 2,
    OP_SHL = 3,
    OP_SHR = 4

class SignedVarReportItem(object):
    def __init__(self, func : Function, sink_insn : MediumLevelILInstruction, op_insn : MediumLevelILInstruction, op_type : SignedOpType, desc : str):
        assert isinstance(func,Function)
        self.func : Function = func
        assert isinstance(sink_insn, MediumLevelILInstruction)
        self.sink_insn : MediumLevelILInstruction = sink_insn
        assert isinstance(op_insn, MediumLevelILInstruction)
        self.op_insn : MediumLevelILInstruction = op_insn
        assert isinstance(op_type, SignedOpType)
        self.op_type = op_type
        self.desc = desc
    
    def __repr__(self):
        return str(self)

    def __str__(self):
        op_type_str = ""
        if self.op_type == SignedOpType.OP_MUL:
            op_type_str = "mul"
        elif self.op_type == SignedOpType.OP_ADD:
            op_type_str = "add"
        elif self.op_type == SignedOpType.OP_SUB:
            op_type_str = "sub"
        
        return "function : %s\nsink : %s\nop : %s\nop type : %s\ndesc : %s" % (
            self.func,
            self.sink_insn,
            self.op_insn,
            op_type_str,
            self.desc
        )


class MediumLevelILInstructionWrapper(object):
    def __init__(self, src : SSAVariable):
        self.operation = MediumLevelILOperation.MLIL_VAR_SSA
        self.src = src

class SignedVarChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "SignedVar"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        self.__sink_funcs = {
            "malloc" : 0,
            "memcpy" : 1,
            "read" : 2,
            "pread" : 2,
            "memmove" : 2,
            "strncpy" : 2
        }
        self.__ptr_size = self.__get_ptr_size()

        for sink_name, index in self.__sink_funcs.items():
            calls : typing.List[MediumLevelILInstruction] = get_call_ssa_instructions_to(module, sink_name)
            for call_insn in calls:
                """只用管函数内的
                """
                params = call_insn.params
                if len(params) < index + 1:
                    continue
                var_insn : MediumLevelILInstruction = params[index]
                if var_insn.operation != MediumLevelILOperation.MLIL_VAR_SSA:
                    continue
                ssa_var : SSAVariable = var_insn.src
                if ssa_var.var.type.signed:
                    self.__on_check_binary_ops(call_insn, ssa_var)
    
    def __is_ptr(self, var : SSAVariable)->bool:
        assert isinstance(var, SSAVariable)
        t : Type = var.var.type
        type_str = str(t)
        """有没有更正常点的方案
        """
        if "*" in type_str:
            return True
        return False
    
    def __equal_to_any_return_var(
        self, 
        var : SSAVariable, 
        insn : MediumLevelILInstruction, 
        maps : typing.Dict[SSAVariable, MediumLevelILInstruction],
        dominator_tree_analysis : DominatorTreeAnalysis,
        equivalent_analysis : EquivalentAnalysis):
        """目前我们暂时认为返回值的valueset都是有问题的，不深入这个问题(可能会非常耗时间)
        
        Arguments:
            var {SSAVariable} -- [description]
            insn {MediumLevelILInstruction} -- [description]
            maps {typing.Dict[SSAVariable, MediumLevelILInstruction]} -- [description]
            dominator_tree_analysis {DominatorTreeAnalysis} -- [description]
            equivalent_analysis {EquivalentAnalysis} -- [description]
        
        Returns:
            [type] -- [description]
        """
        for ret_var, inst in maps.items():
            if dominator_tree_analysis.does_dominate(inst, insn):
                if equivalent_analysis.are_equivalent(ret_var, var, insn):
                    return True
        return False
    
    def __get_ptr_size(self)->int:
        assert isinstance(self.__module, Module)
        if self.__module.arch.name in ("aarch64", "ppc64", "ppc64_le"):
            return 8
        if self.__module.arch.name in ("ppc", "ppc_le", "armv7", "armv7eb", "x86", "mipsel32", "mips32"):
            return 4
        if self.__module.arch.name in ("x86_16"):
            return 2
        assert NotImplementedError("Unsupported arch : %s" %  self.__module.arch.name)
    
    def __set_is_too_large(self, value_set : typing.Set[int])->bool:
        if 0xffffffff in value_set:
            return True
        return False
    
    def __equal_to_parameters(self, var : SSAVariable, insn : MediumLevelILInstruction, func : Function, equivalent_analysis : EquivalentAnalysis)->bool:
        for v in func.parameter_vars.vars:
            ssa_var : SSAVariable = SSAVariable(v, 0)
            if equivalent_analysis.are_equivalent(var, ssa_var, insn):
                return True
        return False
    
    def __on_check_binary_ops(self, insn : MediumLevelILInstruction, ssa_var : SSAVariable):
        func : Function = insn.function.source_function
        _dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(DominatorTreeAnalysis, func)
        _equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(EquivalentAnalysis, func)
        for blk in func.mlil.ssa_form:
            for inst in blk:
                if inst.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    continue
                if not _dominator_tree_analysis.does_dominate(inst, insn):
                    continue
                src_insn : MediumLevelILInstruction = inst.src
                dest_var : SSAVariable = inst.dest
                if not _equivalent_analysis.are_equivalent(ssa_var, dest_var, insn):
                    continue

                """x64...
                """
                if src_insn.operation in (
                    MediumLevelILOperation.MLIL_SX,
                    MediumLevelILOperation.MLIL_ZX,
                    MediumLevelILOperation.MLIL_LOW_PART,
                    MediumLevelILOperation.MLIL_VAR_SSA_FIELD
                    ):
                    src_insn = src_insn.src
                    assert isinstance(src_insn, MediumLevelILInstruction)

                if src_insn.operation not in (
                    MediumLevelILOperation.MLIL_SUB,
                    MediumLevelILOperation.MLIL_MUL,
                    MediumLevelILOperation.MLIL_ADD,
                    MediumLevelILOperation.MLIL_LSL,
                    MediumLevelILOperation.MLIL_LSR
                    ):
                    continue

                left_insn : MediumLevelILInstruction = src_insn.left
                right_insn : MediumLevelILInstruction = src_insn.right

                if left_insn.operation in (
                    MediumLevelILOperation.MLIL_SX,
                    MediumLevelILOperation.MLIL_ZX,
                    MediumLevelILOperation.MLIL_LOW_PART,
                    MediumLevelILOperation.MLIL_VAR_SSA_FIELD
                    ):
                    left_insn = MediumLevelILInstructionWrapper(left_insn.src)
                    
                
                if right_insn.operation in (
                    MediumLevelILOperation.MLIL_SX,
                    MediumLevelILOperation.MLIL_ZX,
                    MediumLevelILOperation.MLIL_LOW_PART,
                    MediumLevelILOperation.MLIL_VAR_SSA_FIELD
                    ):
                    right_insn = MediumLevelILInstructionWrapper(right_insn.src)

                if src_insn.operation == MediumLevelILOperation.MLIL_SUB:
                    state, desc = self.__op_check_sub(func, inst, left_insn, right_insn)
                    if state:
                        rp = SignedVarReportItem(func, insn, inst, SignedOpType.OP_SUB, desc)
                        self.report(rp)
                if src_insn.operation == MediumLevelILOperation.MLIL_ADD:
                    state, desc = self.__op_check_add(func, inst, left_insn, right_insn)
                    if state:
                        rp = SignedVarReportItem(func, insn, inst, SignedOpType.OP_ADD, desc)
                        self.report(rp)
                if src_insn.operation == MediumLevelILOperation.MLIL_MUL:
                    state, desc = self.__op_check_mul(func, inst, left_insn, right_insn)
                    if state:
                        rp = SignedVarReportItem(func, insn, inst, SignedOpType.OP_MUL, desc)
                        self.report(rp)
                if src_insn.operation == MediumLevelILOperation.MLIL_LSL:
                    state, desc = self.__op_check_shift(SignedOpType.OP_SHL, inst, left_insn, right_insn)
                    if state:
                        rp = SignedVarReportItem(func, insn, inst, SignedOpType.OP_SHL, desc)
                        self.report(rp)
                if src_insn.operation == MediumLevelILOperation.MLIL_LSR:
                    state, desc = self.__op_check_shift(SignedOpType.OP_SHR, inst, left_insn, right_insn)
                    if state:
                        rp = SignedVarReportItem(func, insn, inst, SignedOpType.OP_SHR, desc)
                        self.report(rp)
    
    @staticmethod
    def generate_desc(op : SignedOpType, left_insn : MediumLevelILInstruction, left_poss_val :int, right_insn : MediumLevelILInstruction, right_poss_val : int)->str:
        op_name = None
        if op == SignedOpType.OP_ADD:
            op_name = "+"
        elif op == SignedOpType.OP_MUL:
            op_name = "*"
        elif op == SignedOpType.OP_SUB:
            op_name = "-"
        else:
            raise RuntimeError("unknown op type : %s" % str(op))

        if left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            return "left(const) %s right(const) (%d, %d)" % (op_name, left_insn.constant, right_insn.constant)
        elif left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if not right_poss_val is None:
                return "left(const) %s right(ssa_var possible value) (%d, %d)" % (op_name, left_insn.constant, right_poss_val)
            else:
                return "left(const) %s right(ssa_var possible value) (%d, unknown)" % (op_name, left_insn.constant)

        elif left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            if not left_poss_val is None:
                return "left(ssa_var possible value) %s right(const) (%d, %d)" % (op_name, left_poss_val, right_insn.constant)
            else:
                return "left(ssa_var possible value) %s right(const) (unknown, %d)" % (op_name, right_insn.constant)
        elif left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if left_poss_val is None:
                left_poss_val = "unknown"
            if right_poss_val is None:
                right_poss_val = "unknown"
            return "left(ssa_var possible value) %s right(ssa_var possible value) (%s, %s)" % (op_name, left_poss_val, right_poss_val)
        return None
    
    @staticmethod
    def generate_desc2(op : SignedOpType, right_poss_val : int)->str:
        op_name = None
        if op == SignedOpType.OP_SHL:
            op_name = ">>"
        elif op == SignedOpType.OP_SHR:
            op_name = "<<"
        else:
            raise RuntimeError("unknown op type : %s" % str(op))

        if right_poss_val is None:
            right_poss_val = "unknown"
        
        return "left %s right(ssa_var possible value) (%s)" % (op_name, right_poss_val)

    
    def __op_check_shift(
        self, 
        op : SignedOpType, 
        insn : MediumLevelILInstruction,
        left_insn : MediumLevelILInstruction,
        right_insn : MediumLevelILInstruction)->typing.Tuple[bool, str]:

        func : Function = insn.function.source_function
        inst_size : int = insn.size
        _value_set_analysis : SimpleValueSetAnalysis = self.__mam.get_function_analysis(SimpleValueSetAnalysis, func)
        _return_var_analysis : ReturnVarAnalysis = self.__mam.get_function_analysis(ReturnVarAnalysis, func)
        _equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(EquivalentAnalysis, func)
        _dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(DominatorTreeAnalysis, func)
        return_vars_to_insn : typing.Dict[SSAVariable, MediumLevelILInstruction] = _return_var_analysis.get_return_vars_to_insn()
        if right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if self.__is_ptr(right_insn.src):
                return False, None
            if self.__equal_to_any_return_var(right_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            right_value_set = _value_set_analysis.get_state_of(right_insn.src)
            right_from_param = self.__equal_to_parameters(right_insn.src, insn, func, _equivalent_analysis)
            if self.__set_is_too_large(right_value_set) and not right_from_param:
                return False, None
            if len(right_value_set):
                for right_value in right_value_set:
                    if right_value >= inst_size * 8:
                        return True, SignedVarChecker.generate_desc2(op, right_value)
            elif right_value_set:
                return True, SignedVarChecker.generate_desc2(op, None)
        
        return False, None
        
    
    def __op_check_sub(self, owner : Function, insn : MediumLevelILInstruction, left_insn : MediumLevelILInstruction, right_insn : MediumLevelILInstruction)->typing.Tuple[bool, str]:
        
        func : Function = insn.function.source_function
        _value_set_analysis : SimpleValueSetAnalysis = self.__mam.get_function_analysis(SimpleValueSetAnalysis, func)
        _return_var_analysis : ReturnVarAnalysis = self.__mam.get_function_analysis(ReturnVarAnalysis, func)
        _equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(EquivalentAnalysis, func)
        _dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(DominatorTreeAnalysis, func)
        return_vars_to_insn : typing.Dict[SSAVariable, MediumLevelILInstruction] = _return_var_analysis.get_return_vars_to_insn()
        if left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            """我不认为会有这种情况
            """
            if left_insn.constant > right_insn.constant:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_SUB, left_insn, None, right_insn, None)
        elif left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if self.__is_ptr(right_insn.src):
                return False, None
            if self.__equal_to_any_return_var(right_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            left_constant = left_insn.constant
            right_value_set = _value_set_analysis.get_state_of(right_insn.src)
            right_from_param = self.__equal_to_parameters(right_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(right_value_set) and not right_from_param:
                """真实的例子:win32k早期有很多来自参数的整数溢出,但是参数值无法求出具体范围
                """
                return False, None
            if len(right_value_set):
                for right_value in right_value_set:
                    if left_constant < right_value:
                        return True, SignedVarChecker.generate_desc(SignedOpType.OP_SUB, left_insn, None, right_insn, right_value)
            else:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_SUB, left_insn, None, right_insn, None)
                
        elif left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            if self.__is_ptr(left_insn.src):
                return False, None
            if self.__equal_to_any_return_var(left_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            right_const = right_insn.constant
            
            left_value_set = _value_set_analysis.get_state_of(left_insn.src)
            left_from_param = self.__equal_to_parameters(left_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(left_value_set) and not left_from_param:
                return False, None
            if len(left_value_set):
                for left_value in left_value_set:
                    if left_value < right_const:
                        return True, SignedVarChecker.generate_desc(SignedOpType.OP_SUB, left_insn, left_value, right_insn, None)
            else:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_SUB, left_insn, None, right_insn, None)


        elif left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if self.__is_ptr(left_insn.src) or self.__is_ptr(right_insn.src):
                return False, None
            if self.__equal_to_any_return_var(left_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            if self.__equal_to_any_return_var(right_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            left_value_set = _value_set_analysis.get_state_of(left_insn.src)
            right_value_set = _value_set_analysis.get_state_of(right_insn.src)
            left_from_param  = self.__equal_to_parameters(left_insn.src, insn, owner, _equivalent_analysis)
            right_from_param = self.__equal_to_parameters(right_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(left_value_set) and not left_from_param:
                return False, None
            if self.__set_is_too_large(right_value_set) and not right_from_param:
                return False, None
            if len(left_value_set) or len(right_value_set):
                for left_value in left_value_set:
                    for right_value in right_value_set:
                        if left_value < right_value:
                            return True, SignedVarChecker.generate_desc(SignedOpType.OP_SUB, left_insn, left_value, right_insn, right_value)
            else:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_SUB, left_insn, None, right_insn, None)

        return False, None
    
    def __op_check_add(self, owner : Function, insn : MediumLevelILInstruction, left_insn : MediumLevelILInstruction, right_insn : MediumLevelILInstruction)->typing.Tuple[bool,str]:
        
        func : Function = insn.function.source_function
        _value_set_analysis : SimpleValueSetAnalysis = self.__mam.get_function_analysis(SimpleValueSetAnalysis, func)
        _return_var_analysis : ReturnVarAnalysis = self.__mam.get_function_analysis(ReturnVarAnalysis, func)
        _equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(EquivalentAnalysis, func)
        _dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(DominatorTreeAnalysis, func)
        return_vars_to_insn : typing.Dict[SSAVariable, MediumLevelILInstruction] = _return_var_analysis.get_return_vars_to_insn()
        if left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            """我不认为会有这种情况
            """
            if left_insn.constant + right_insn.constant > 0x7fffffff:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_ADD, left_insn, None, right_insn, None)
        elif left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if self.__is_ptr(right_insn.src):
                return False, None
            if self.__equal_to_any_return_var(right_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            left_constant = left_insn.constant
            right_value_set = _value_set_analysis.get_state_of(right_insn.src)
            right_from_param = self.__equal_to_parameters(right_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(right_value_set) and not right_from_param:
                return False, None
            if len(right_value_set):
                for right_value in right_value_set:
                    if left_constant + right_value > 0x7fffffff:
                        return True, SignedVarChecker.generate_desc(SignedOpType.OP_ADD, left_insn, None, right_insn, right_value)
            else:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_ADD, left_insn, None, right_insn, None)

        elif left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            if self.__is_ptr(left_insn.src):
                return False, None
            if self.__equal_to_any_return_var(left_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            right_const = right_insn.constant
            left_value_set = _value_set_analysis.get_state_of(left_insn.src)
            left_from_param = self.__equal_to_parameters(left_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(left_value_set) and not left_from_param:
                return False, None
            if len(left_value_set):
                for left_value in left_value_set:
                    if left_value + right_const > 0x7fffffff:
                        return True, SignedVarChecker.generate_desc(SignedOpType.OP_ADD, left_insn, left_value, right_insn, None)
            else:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_ADD, left_insn, None, right_insn, None)
                
        elif left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if self.__is_ptr(left_insn.src) or self.__is_ptr(right_insn.src):
                return False, None
            if self.__equal_to_any_return_var(left_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            if self.__equal_to_any_return_var(right_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            left_value_set = _value_set_analysis.get_state_of(left_insn.src)
            right_value_set = _value_set_analysis.get_state_of(right_insn.src)
            left_from_param = self.__equal_to_parameters(left_insn.src, insn, owner, _equivalent_analysis)
            right_from_param = self.__equal_to_parameters(right_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(left_value_set) and not left_from_param:
                return False, None
            if self.__set_is_too_large(right_value_set) and not right_from_param:
                return False, None
            if len(left_value_set) or len(right_value_set):
                for left_value in left_value_set:
                    for right_value in right_value_set:
                        if left_value + right_value > 0x7fffffff:
                            return True, SignedVarChecker.generate_desc(SignedOpType.OP_ADD, left_insn, left_value, right_insn, right_value)
            else:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_ADD, left_insn, None, right_insn, None)
        
        return False, None
    
    def __op_check_mul(self, owner : Function, insn : MediumLevelILInstruction, left_insn : MediumLevelILInstruction, right_insn : MediumLevelILInstruction)->typing.Tuple[bool,str]:

        func : Function = insn.function.source_function
        if left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            val = left_insn.constant * right_insn.constant
            if val >= 0x7fffffff:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_MUL, left_insn, None, right_insn, None)
        
        value_set_analysis : SimpleValueSetAnalysis = self.__mam.get_function_analysis(SimpleValueSetAnalysis, func)
        _return_var_analysis : ReturnVarAnalysis = self.__mam.get_function_analysis(ReturnVarAnalysis, func)
        _equivalent_analysis : EquivalentAnalysis = self.__mam.get_function_analysis(EquivalentAnalysis, func)
        _dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(DominatorTreeAnalysis, func)
        return_vars_to_insn : typing.Dict[SSAVariable, MediumLevelILInstruction] = _return_var_analysis.get_return_vars_to_insn()
        if left_insn.operation == MediumLevelILOperation.MLIL_CONST and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if self.__is_ptr(right_insn.src):
                return False, None
            if self.__equal_to_any_return_var(right_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            vals = value_set_analysis.get_state_of(right_insn.src)
            right_from_param = self.__equal_to_parameters(right_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(vals) and not right_from_param:
                return False, None
            if len(vals):
                for val in vals:
                    if val * left_insn.constant >= 0x7fffffff:
                        return True, SignedVarChecker.generate_desc(SignedOpType.OP_MUL, left_insn, None, right_insn, val)
            elif right_from_param:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_MUL, left_insn, None, right_insn, None)
        
        if left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_CONST:
            if self.__is_ptr(left_insn.src):
                return False, None
            if self.__equal_to_any_return_var(left_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            vals = value_set_analysis.get_state_of(left_insn.src)
            left_from_param = self.__equal_to_parameters(left_insn.src, insn, owner, _equivalent_analysis)
            if self.__set_is_too_large(vals) and not left_from_param:
                return False, None
            if len(vals):
                for val in vals:
                    if val * right_insn.constant >= 0x7fffffff:
                        return True, SignedVarChecker.generate_desc(SignedOpType.OP_MUL, left_insn, val, right_insn, None)
            elif left_from_param:
                return True, SignedVarChecker.generate_desc(SignedOpType.OP_MUL, left_insn, None, right_insn, None)
        
        if left_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and right_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if self.__is_ptr(left_insn.src) or self.__is_ptr(right_insn.src):
                return False, None
            if self.__equal_to_any_return_var(left_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            if self.__equal_to_any_return_var(right_insn.src, insn, return_vars_to_insn, _dominator_tree_analysis, _equivalent_analysis):
                return False, None
            left_vals = value_set_analysis.get_state_of(left_insn.src)
            right_vals = value_set_analysis.get_state_of(right_insn.src)
            if self.__set_is_too_large(left_vals) and not self.__equal_to_parameters(left_insn.src, insn, owner, _equivalent_analysis):
                return False, None
            if self.__set_is_too_large(right_vals) and not self.__equal_to_parameters(right_insn.src, insn, owner, _equivalent_analysis):
                return False, None
            for left_val in left_vals:
                for right_val in right_vals:
                    if left_val * right_val >= 0x7fffffff:
                        return True, SignedVarChecker.generate_desc(SignedOpType.OP_MUL, left_insn, left_val, right_insn, right_val)

        return False, None


