import enum
import subprocess
import re
import os
import logging
import tempfile
import typing
import queue

from .basic import FunctionAnalysis, AnalysisManager, Module, Function, FunctionAnalysisManager
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from binaryninja.function import Variable
from binaryninja.enums import VariableSourceType
from collections import defaultdict
import abc


logger = logging.Logger(__name__)


StandardSSAVariable = typing.Union[MediumLevelILInstruction,
                                   SSAVariable, Variable]
# BinaryNinja对SSA的定义不太一致，LLVM的SSA定义是
# $a = ..
# $b = add $c, 0x1000
# 这种每个指令定义一个SSA variable的情况。

# BinaryNinja里的SSA则是类似这样的
# $d = $a * 2 + $b - $c
# 这里实际上我们需要得到是前者的分析结果 （比如我们需要获得 $x = add($a+$b, 100)
# 处，add($a+$b)可能的结果，但是因为这里的结果不一定是SSAVariable, 而可能是一个表达式，因此不能搞。。。）

# 但是我们并不能全部转换成LLVM形式的SSA，因为BinaryNinja里有MLIL_CALL_SSA这种,可能返回多个数值的情况，这种情况下，这个分析就忽略这个结果。


class UnionFindSet(object):
    def __init__(self):
        self._parent = {}
        return

    def get_parent(self, target):
        if target not in self._parent:
            self._parent[target] = target
        return self._parent[target]

    def get_root(self, target):
        if self.get_parent(target) == target:
            return target
        root = self.get_root(self.get_parent(target))
        self._parent[target] = root
        return root

    def union(self, left, right):
        """
        把right和left union在一起，维持left的root
        """
        root1 = self.get_root(left)
        root2 = self.get_root(right)
        self._parent[root2] = root1

    def same(self, left, right):
        return self.get_root(left) == self.get_root(right)


class KeyedDict(dict):
    def __init__(self, key_function, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._key_function = key_function

    def __missing__(self, key):
        return self._key_function(key)


class SSAUseDefineAnalysis(FunctionAnalysis):

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self._function = function
        self._users = defaultdict(set)
        self._mem_vars = set()
        self._mem_versions = set()
        self._var_to_layer_version: typing.Dict[Variable,
                                                typing.Dict[int, SSAVariable]] = {}

        q = queue.Queue()
        visited = set()

        def expand(i):
            if i in visited:
                return
            q.put(i)
            visited.add(i)

        for inst in self._function.mlil.ssa_form.instructions:
            expand(inst)

        while not q.empty():
            i = q.get()
            assert isinstance(
                i, (MediumLevelILInstruction, Variable, SSAVariable))
            if not isinstance(i, MediumLevelILInstruction):
                continue

            name_type_list = MediumLevelILInstruction.ILOperations[i.operation]
            for name, operand_type in name_type_list:

                if name in ["src_memory", "dest_memory"]:
                    v = getattr(i, name)
                    if operand_type == "int_list":
                        for vv in v:
                            self._mem_versions.add(vv)
                    elif operand_type == "int":
                        self._mem_versions.add(v)
                    else:
                        assert False, operand_type

                if operand_type in ["var", "expr", "var_ssa"]:
                    expand(getattr(i, name))
                elif operand_type in ["int", "float", "double", "int_list", "intrinsic"]:
                    pass
                elif operand_type == "var_ssa_dest_and_src":
                    expand(getattr(i, "dest"))
                    expand(getattr(i, name))

                elif operand_type in ["expr_list", "var_ssa_list", "var_list"]:
                    for expr in getattr(i, name):
                        expand(expr)
                else:
                    assert False, "Unknown operand_type %s" % operand_type

        def add_user(used, user):
            assert used is not None
            assert user is not None
            self._users[used].add(user)

        self._all = set(visited)

        # it's possible that a parameter is not used
        for parameter_ssa_var in map(
            lambda var: SSAVariable(
                var, 0), function.parameter_vars.vars):
            self._all.add(parameter_ssa_var)

        # for inst in list(filter(lambda inst: isinstance(inst, MediumLevelILInstruction), self._all)):
        #    if inst.operation in [MediumLevelILOperation.MLIL_SET_VAR_ALIASED, MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD]:
        #        for ssa_var in [getattr(inst, "dest"), getattr(inst, "prev")]: # 对于这种类型的指令。。这个实际上是SSA分析失败的结果，需要依赖MLIL_MEM_PHI进行phi
        #            self._mem_vars.add(ssa_var.var)
        #            self._mem_versions.add(ssa_var.version)

        for ssa_var in list(
            filter(
                lambda inst: isinstance(
                    inst,
                    SSAVariable),
                self._all)):
            if ssa_var.var.index == 0 and ssa_var.var.source_type == VariableSourceType.StackVariableSourceType:
                x = self._function.mlil.get_ssa_var_definition(ssa_var)
                y = self._function.mlil.get_ssa_memory_definition(ssa_var.version)
                if x is not None and x == y:
                    self._mem_vars.add(ssa_var.var)
                    self._mem_versions.add(ssa_var.version)

        for mem_version_number in self._mem_versions:
            for var in self._mem_vars:
                self._all.add(SSAVariable(var, mem_version_number))

        for inst in list(
            filter(
                lambda inst: isinstance(
                    inst,
                    MediumLevelILInstruction),
                self._all)):
            for used in self._get_used_of(inst):
                add_user(used, inst)
            for user in self._get_users_of(inst):
                add_user(inst, user)

            if inst.operation == MediumLevelILOperation.MLIL_MEM_PHI:
                for mem_version_number in inst.src_memory:
                    for used_var in self._mem_vars:
                        add_user(
                            SSAVariable(
                                used_var,
                                mem_version_number),
                            inst)

        # OK, now get_users_of is good to use...
        # Let's use it to calculate where the location for each
        # StandardSSAVariable is defined?
        instructions = set(self._function.mlil.ssa_form.instructions)
        self.__definiation_point = UnionFindSet()
        us = self.__definiation_point
        for var in self._all:
            if not isinstance(var, MediumLevelILInstruction):
                continue
            if var in instructions:
                for user in self.get_users_of(var):
                    us.union(var, user)
            else:
                for user in self.get_users_of(var):
                    a = us.get_root(user)
                    b = us.get_root(var)
                    if a in instructions and b in instructions:
                        assert a == b, (a, b, user, var)
                    us.union(user, var)

        for var in self._all:
            if var in instructions:
                assert us.get_root(var) == var, (us.get_root(var), var)
            else:
                if isinstance(var, MediumLevelILInstruction):
                    #assert us.get_root(var) in instructions, (us.get_root(var), instructions, var.function.source_function.name, hex(var.address))
                    pass
        self.__instructions = instructions

    def get_users_of(
            self,
            used_value: StandardSSAVariable) -> typing.Sequence[StandardSSAVariable]:
        assert used_value in self._all, "%s is not belong to current_function?" % used_value
        return list(self._users[used_value])

    def get_all_variables(self) -> typing.Sequence[StandardSSAVariable]:
        return list(self._all)

    def get_definition_instruction(
            self,
            var: StandardSSAVariable) -> typing.Optional[MediumLevelILInstruction]:
        """返回binaryninja定义下，该变量被定义的指令，可能为None"""
        inst = self.__definiation_point.get_root(var)
        if inst in self.__instructions:
            return inst
        return None

    def get_ssa_var_of_memory_version(
            self,
            version: int,
            ssa_var: SSAVariable) -> typing.Optional[SSAVariable]:
        var = ssa_var.var
        assert var in self._mem_vars
        return SSAVariable(ssa_var.var, version)

    def get_all_ssa_var_in_memory_version(
            self, version: int) -> typing.Sequence[SSAVariable]:
        assert version in self._mem_versions
        return list(map(lambda var: SSAVariable(var, version), self._mem_vars))

    @classmethod
    def _get_used_of(
            cls,
            inst: MediumLevelILInstruction) -> typing.Sequence[StandardSSAVariable]:
        """
        return the direct used values of a instructions
        """
        assert isinstance(inst, MediumLevelILInstruction)
        if inst.operation in [
                MediumLevelILOperation.MLIL_SET_VAR,
                MediumLevelILOperation.MLIL_SET_VAR_FIELD,
                MediumLevelILOperation.MLIL_SET_VAR_SPLIT,
                MediumLevelILOperation.MLIL_SET_VAR_SSA,
                MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA,
                MediumLevelILOperation.MLIL_SET_VAR_ALIASED]:
            return [inst.src]
        elif inst.operation in [MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD,
                                MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD]:
            return [inst.prev, inst.src]
        elif inst.operation in [MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_TAILCALL,
                                MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA]:
            return list(inst.params) + [inst.dest]
        elif inst.operation in [MediumLevelILOperation.MLIL_SYSCALL, MediumLevelILOperation.MLIL_SYSCALL_SSA]:
            return list(inst.params)
        elif inst.operation in [MediumLevelILOperation.MLIL_CALL_UNTYPED, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
                                MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA]:
            # FIXME: we may need to add inst.params.src #
            # 这里目前的建议就是这个指令放弃吧...这里我猜测是没有进行类型推断前的IL?,应该不会出现吧。。
            return [inst.params, inst.dest]
        elif inst.operation in [MediumLevelILOperation.MLIL_SYSCALL_UNTYPED, MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA]:
            # FIXME: we may need to add inst.params.src #
            # 这里目前的建议就是这个指令放弃吧...这里我猜测是没有进行类型推断前的IL?,应该不会出现吧。。
            return [inst.params]
        elif inst.operation in [MediumLevelILOperation.MLIL_CALL_PARAM, MediumLevelILOperation.MLIL_CALL_PARAM_SSA,
                                MediumLevelILOperation.MLIL_VAR_PHI]:
            return inst.src
        elif inst.operation in [MediumLevelILOperation.MLIL_CALL_OUTPUT, MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA]:
            return []
        elif inst.operation in [MediumLevelILOperation.MLIL_RET]:
            return inst.src
        result = []
        for operand in inst.operands:
            if (isinstance(operand, Variable)) or (
                    isinstance(operand, SSAVariable)):
                result.append(operand)
            elif isinstance(operand, MediumLevelILInstruction):
                result.append(operand)
        return result

    @classmethod
    def _get_users_of(
            cls,
            inst: MediumLevelILInstruction) -> typing.Sequence[StandardSSAVariable]:
        """List of variables written by instruction"""
        if inst.operation in [
                MediumLevelILOperation.MLIL_SET_VAR,
                MediumLevelILOperation.MLIL_SET_VAR_FIELD,
                MediumLevelILOperation.MLIL_SET_VAR_SSA,
                MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD,
                MediumLevelILOperation.MLIL_SET_VAR_ALIASED,
                MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD,
                MediumLevelILOperation.MLIL_VAR_PHI]:
            return [inst.dest]
        elif inst.operation in [MediumLevelILOperation.MLIL_SET_VAR_SPLIT, MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA]:
            return [inst.high, inst.low]
        elif inst.operation in [MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_SYSCALL, MediumLevelILOperation.MLIL_TAILCALL]:
            return inst.output
        elif inst.operation in [MediumLevelILOperation.MLIL_CALL_UNTYPED, MediumLevelILOperation.MLIL_SYSCALL_UNTYPED, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
                                MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
                                MediumLevelILOperation.MLIL_SYSCALL_SSA, MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA,
                                MediumLevelILOperation.MLIL_TAILCALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA]:
            return [inst.output] + list(inst.output.dest)
        elif inst.operation in [MediumLevelILOperation.MLIL_CALL_OUTPUT, MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA]:
            return inst.dest
        return []

    @staticmethod
    def is_expression_instruction(inst: MediumLevelILInstruction) -> bool:
        if inst.operation in [
                MediumLevelILOperation.MLIL_LOAD,
                MediumLevelILOperation.MLIL_LOAD_STRUCT,
                MediumLevelILOperation.MLIL_VAR,
                MediumLevelILOperation.MLIL_VAR_FIELD,
                MediumLevelILOperation.MLIL_VAR_SPLIT,
                MediumLevelILOperation.MLIL_ADDRESS_OF,
                MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD,
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR,
                MediumLevelILOperation.MLIL_EXTERN_PTR,
                MediumLevelILOperation.MLIL_FLOAT_CONST,

                MediumLevelILOperation.MLIL_ADD,
                MediumLevelILOperation.MLIL_ADC,
                MediumLevelILOperation.MLIL_SUB,
                MediumLevelILOperation.MLIL_SBB,
                MediumLevelILOperation.MLIL_AND,
                MediumLevelILOperation.MLIL_OR,
                MediumLevelILOperation.MLIL_XOR,
                MediumLevelILOperation.MLIL_LSL,
                MediumLevelILOperation.MLIL_LSR,
                MediumLevelILOperation.MLIL_ASR,
                MediumLevelILOperation.MLIL_ROL,
                MediumLevelILOperation.MLIL_RLC,
                MediumLevelILOperation.MLIL_ROR,
                MediumLevelILOperation.MLIL_RRC,
                MediumLevelILOperation.MLIL_MUL,
                MediumLevelILOperation.MLIL_MULU_DP,
                MediumLevelILOperation.MLIL_MULS_DP,
                MediumLevelILOperation.MLIL_DIVU,
                MediumLevelILOperation.MLIL_DIVU_DP,
                MediumLevelILOperation.MLIL_DIVS,
                MediumLevelILOperation.MLIL_DIVS_DP,
                MediumLevelILOperation.MLIL_MODU,
                MediumLevelILOperation.MLIL_MODS_DP,
                MediumLevelILOperation.MLIL_MODS,
                MediumLevelILOperation.MLIL_MODS_DP,

                MediumLevelILOperation.MLIL_NEG,
                MediumLevelILOperation.MLIL_NOT,
                MediumLevelILOperation.MLIL_SX,
                MediumLevelILOperation.MLIL_ZX,
                MediumLevelILOperation.MLIL_LOW_PART,
                MediumLevelILOperation.MLIL_CALL_PARAM,

                MediumLevelILOperation.MLIL_CMP_E,
                MediumLevelILOperation.MLIL_CMP_NE,
                MediumLevelILOperation.MLIL_CMP_SLT,
                MediumLevelILOperation.MLIL_CMP_ULT,
                MediumLevelILOperation.MLIL_CMP_SLE,
                MediumLevelILOperation.MLIL_CMP_ULE,
                MediumLevelILOperation.MLIL_CMP_SGE,
                MediumLevelILOperation.MLIL_CMP_UGE,
                MediumLevelILOperation.MLIL_CMP_SGT,
                MediumLevelILOperation.MLIL_CMP_UGT,
                MediumLevelILOperation.MLIL_TEST_BIT,
                MediumLevelILOperation.MLIL_BOOL_TO_INT,
                MediumLevelILOperation.MLIL_ADD_OVERFLOW,

                MediumLevelILOperation.MLIL_FADD,
                MediumLevelILOperation.MLIL_FSUB,
                MediumLevelILOperation.MLIL_FMUL,
                MediumLevelILOperation.MLIL_FDIV,
                MediumLevelILOperation.MLIL_FNEG,
                MediumLevelILOperation.MLIL_FABS,
                MediumLevelILOperation.MLIL_FLOAT_TO_INT,
                MediumLevelILOperation.MLIL_INT_TO_FLOAT,
                MediumLevelILOperation.MLIL_FLOAT_CONV,
                MediumLevelILOperation.MLIL_ROUND_TO_INT,
                MediumLevelILOperation.MLIL_FLOOR,
                MediumLevelILOperation.MLIL_CEIL,
                MediumLevelILOperation.MLIL_FTRUNC,
                MediumLevelILOperation.MLIL_FCMP_E,
                MediumLevelILOperation.MLIL_FCMP_NE,
                MediumLevelILOperation.MLIL_FCMP_LT,
                MediumLevelILOperation.MLIL_FCMP_LE,
                MediumLevelILOperation.MLIL_FCMP_GE,
                MediumLevelILOperation.MLIL_FCMP_GT,
                MediumLevelILOperation.MLIL_FCMP_O,
                MediumLevelILOperation.MLIL_FCMP_UO,

                MediumLevelILOperation.MLIL_CALL_PARAM_SSA,
                MediumLevelILOperation.MLIL_LOAD_SSA,
                MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA,
        ]:
            return True
        return False
