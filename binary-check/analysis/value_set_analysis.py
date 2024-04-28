from analysis.basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, Module
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from analysis.dataflow_analysis import StandardSSAVariable
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis

from binaryninja.enums import Endianness

import abc

import typing
from contextlib import contextmanager

from . import utils

# @contextmanager


def mask(bits: int) -> int:
    return (1 << bits) - 1


class SimpleValueSet(set, SSADataFlowState):
    """
    len(self) means top, i.e. it's possible that any value in the set
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._too_big = False
        if len(self) == 0:
            self._too_big = True
        if len(self) > 100:
            self.clear()
            self._too_big = True

    def is_too_big(self):
        return self._too_big

    def set_too_big(self, too_big=True):
        self._too_big = too_big


class SimpleValueSetAnalysis(SSADataFlowAnalysisBase):

    def meet(self, target_ssa_var: SSAVariable, *
             args: typing.Sequence[SimpleValueSet]) -> SimpleValueSet:
        for v in args:
            if v.is_too_big():
                return v
        retv = set()
        for v in args:
            retv |= v
        return SimpleValueSet(retv)

    def join(self, target_ssa_var: SSAVariable, *
             args: typing.Sequence[SimpleValueSet]) -> SimpleValueSet:
        for v in args:
            if v.is_too_big():
                continue
            else:
                retv = set(v)
                break
        else:
            return SimpleValueSet()

        for v in args:
            if v.is_too_big():
                continue
            retv &= v
        assert len(retv) > 0  # 不同来源的结果不没有任何交集？说明这个变量被def的地方根本没跑过？
        return SimpleValueSet(retv)

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self._equivalent_analysis: EquivalentAnalysis = fam.get_function_analysis(
            EquivalentAnalysis)
        self._use_def_analysis: SSAUseDefineAnalysis = fam.get_function_analysis(
            SSAUseDefineAnalysis)
        self._fam = fam
        retv = super().run_on_function(function, fam)
        return retv

    def get_default_state(self, var: StandardSSAVariable) -> SimpleValueSet:
        return SimpleValueSet()

    def _binary_trans_helper(self,
                             func: typing.Callable,
                             inst: MediumLevelILInstruction,
                             a: StandardSSAVariable,
                             b: StandardSSAVariable) -> typing.Iterable[typing.Tuple[int]]:
        aa = self.get_state_of(a)
        bb = self.get_state_of(b)
        if self._equivalent_analysis.are_equivalent(a, b, inst):
            yield from map(lambda x_x: func(*x_x), map(lambda x: (x, x), aa))
            # NOTE: 理论上我们其实可以直接只写上面一行，而忽略下面这行：
            # 因为当前指令如果use了b而触发trans，从而进入本函数，我们可能存在只使用aa更新状态的情况。
            # 当然，因为a和b是等价的，我们迟早会因为a的状态被再次更新，而再次进入本函数并正确的迭代。
            # 但这样的话我们为什么不早一点呢？
            yield from map(lambda x_x: func(*x_x), map(lambda x: (x, x), bb))
            return  # 别忘了这个return
        for aaa in aa:
            for bbb in bb:
                yield func(aaa, bbb)

    def _unary_trans_helper(self, func: typing.Callable,
                            a: StandardSSAVariable) -> typing.Iterable[typing.Tuple[int]]:
        aa = self.get_state_of(a)
        yield from map(func, aa)

    def trans(self, inst: MediumLevelILInstruction) -> bool:
        if inst.operation == MediumLevelILOperation.MLIL_ZX:
            # NOTE: there is some situation that make inst.size < inst.src.size
            values = list(self.get_state_of(inst.src))
            new_values = []
            for v in values:
                v &= (mask(inst.size * 8))
                new_values.append(v)
            self.update_var_state(inst, SimpleValueSet(new_values))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_SX:
            # assert inst.size >= inst.src.size, (inst, inst.function.source_function.name)
            # NOTE: there is some situation that make inst.size < inst.src.size
            if inst.size <= inst.src.size:
                values = list(self.get_state_of(inst.src))
                new_values = []
                for v in values:
                    v &= (mask(inst.size * 8))
                    new_values.append(v)
                self.update_var_state(inst, SimpleValueSet(new_values))
                return True

            values = list(self.get_state_of(inst.src))
            new_values = []
            for v in values:
                if v & (1 << (inst.src.size * 8 - 1)):  # Negative
                    v |= (1 << (inst.size * 8)) - (1 << (inst.src.size * 8))
                new_values.append(v)
            self.update_var_state(inst, SimpleValueSet(new_values))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_IMPORT:

            byte_sequence = utils.get_bytes_at(
                self._fam.get_module(), inst.constant, inst.size)
            if byte_sequence is None:
                return True  # Do not update this value...
            assert len(byte_sequence) in [4, 8]

            module = self._fam.get_module()
            assert module.endianness in [
                Endianness.BigEndian, Endianness.LittleEndian]

            ptr = 0
            if module.endianness == Endianness.LittleEndian:
                for v in byte_sequence[::-1]:
                    ptr *= 256
                    ptr += v
            else:
                for v in byte_sequence:
                    ptr *= 256
                    ptr += v

            self.update_var_state(inst, SimpleValueSet(set([ptr])))
            return True

        if inst.operation in [
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR]:
            self.update_var_state(inst, SimpleValueSet(set([inst.constant])))
            return True

        if inst.operation in utils.COMMON_BINARY_MEDIUM_LEVEL_IL_OPERATION_TO_OPERATOR:
            func = utils.COMMON_BINARY_MEDIUM_LEVEL_IL_OPERATION_TO_OPERATOR[inst.operation]
            s = self._binary_trans_helper(
                lambda x,
                y: func(
                    x,
                    y) & mask(
                    inst.size *
                    8),
                inst,
                inst.left,
                inst.right)
            self.update_var_state(inst, SimpleValueSet(s))
            return True

        if inst.operation in utils.COMMON_UNARY_MEDIUM_LEVEL_IL_OPERATION_TO_OPERATOR:
            func = utils.COMMON_UNARY_MEDIUM_LEVEL_IL_OPERATION_TO_OPERATOR[inst.operation]
            s = self._unary_trans_helper(
                lambda x: func(x) & mask(
                    inst.size * 8), inst.src)
            self.update_var_state(inst, SimpleValueSet(s))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
            module = self._fam.get_module()
            assert module.endianness in [
                Endianness.BigEndian, Endianness.LittleEndian]

            if module.endianness == Endianness.LittleEndian:
                shift = inst.offset * 8
            else:
                if inst.src.var.type.width is None:
                    return

                shift = (inst.src.var.type.width - inst.offset - inst.size)
                if shift < 0: # issue #6
                    return

            s = self._unary_trans_helper(
                lambda x: (
                    x >> shift) & mask(
                    inst.size * 8),
                inst.src)
            self.update_var_state(inst, SimpleValueSet(s))
            return True
