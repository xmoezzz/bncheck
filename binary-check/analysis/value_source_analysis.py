import binaryninja

from analysis.basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, Module
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable, MediumLevelILFunction
from binaryninja import Endianness, BinaryView
from analysis.dataflow_analysis import StandardSSAVariable
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis
from analysis.exp_tree_analysis import ExpTreeFunctionAnalysis

import abc
import analysis.utils
import utils.base_tool

import logging
import typing
import enum


logger = logging.getLogger(__name__)


class ValueSourceType(enum.IntEnum):
    PARAM_SOURCE = 0,
    RETURN_SOURCE = 1,
    CONST_INT_SOURCE = 2,
    CONST_PTR_SOURCE = 3,
    IMPORT_SOURCE = 4,
    UNKNOWN_SOURCE = 5


class ValueSourceBase(abc.ABC):
    @abc.abstractmethod
    def get_type(self) -> ValueSourceType:
        pass

    def get_define_insn(self) -> int:
        """which insn(index) defines this variable?

        Returns:
            int -- [description]
        """
        pass

    @abc.abstractmethod
    def __eq__(self, other):
        pass

    @abc.abstractmethod
    def __hash__(self, other):
        pass


class ParamValueSource(ValueSourceBase):
    def __init__(self, name, index):
        self.source_type = ValueSourceType.PARAM_SOURCE
        self.name = name
        self.index = index

    def __eq__(self, other):
        return self.source_type == other.source_type and \
            self.name == other.name and \
            self.index == other.index

    def __hash__(self):
        return hash((self.source_type, self.name, self.index))

    def get_type(self) -> ValueSourceType:
        return self.source_type

    def get_name(self) -> str:
        return self.name

    def get_index(self) -> int:
        return self.index

    def get_define_insn(self) -> int:
        return -1


class ReturnValueSource(ValueSourceBase):
    def __init__(self, index, offset, size, insn, define_insn):
        self.source_type = ValueSourceType.RETURN_SOURCE
        self.index = index
        self.callee_insn = insn
        self.define_insn = define_insn
        self.offset = offset
        self.size = size

    def __eq__(self, other):
        return self.source_type == other.source_type and self.index == other.index and self.callee_insn == other.callee_insn and self.define_insn == other.define_insn and self.offset == other.offset and self.size == other.size

    def __hash__(self):
        return hash(
            (self.source_type,
             self.index,
             self.callee_insn,
             self.define_insn,
             self.offset,
             self.size))

    def get_type(self) -> ValueSourceType:
        return self.source_type

    def get_index(self) -> int:
        return self.index

    def get_define_insn(self) -> int:
        return self.define_insn

    def get_offset(self) -> int:
        """get offset in byte

        Returns:
            int -- offset
        """
        return self.offset


class ConstIntValueSource(ValueSourceBase):
    def __init__(self, value, define_insn):
        self.source_type = ValueSourceType.CONST_INT_SOURCE
        self.value = value
        self.define_insn = define_insn

    def __eq__(self, other):
        return self.source_type == other.source_type and self.define_insn == other.define_insn and self.value == other.value

    def __hash__(self):
        return hash((self.source_type, self.value, self.define_insn))

    def get_type(self) -> ValueSourceType:
        return self.source_type

    def get_value(self):
        return self.value

    def get_define_insn(self) -> int:
        return self.define_insn


class ConstPtrValueSource(ValueSourceBase):
    def __init__(self, value, define_insn):
        self.source_type = ValueSourceType.CONST_PTR_SOURCE
        self.value = value
        self.define_insn = define_insn

    def __eq__(self, other):
        return self.source_type == other.source_type and self.define_insn == other.define_insn and self.value == other.value

    def __hash__(self):
        return hash((self.source_type, self.value, self.define_insn))

    def get_type(self) -> ValueSourceType:
        return self.source_type

    def get_value(self):
        return self.value

    def get_define_insn(self) -> int:
        return self.define_insn


class ImportValueSource(ValueSourceBase):
    def __init__(self, address, define_insn):
        self.source_type = ValueSourceType.IMPORT_SOURCE
        self.address = address
        self.define_insn = define_insn

    def __eq__(self, other):
        return self.source_type == other.source_type and self.define_insn == other.define_insn and self.address == other.address

    def __hash__(self):
        return hash((self.source_type, self.address, self.define_insn))

    def get_type(self) -> ValueSourceType:
        return self.source_type

    def get_address(self):
        return self.address

    def get_define_insn(self) -> int:
        return self.define_insn


class UnknownValueSource(ValueSourceBase):
    def __init__(self, var, define_insn):
        self.source_type = ValueSourceType.CONST_PTR_SOURCE
        self.var = var
        self.define_insn = define_insn

    def __eq__(self, other):
        return self.source_type == other.source_type and self.define_insn == other.define_insn and self.var == other.var

    def __hash__(self):
        return hash((self.source_type, self.var, self.define_insn))

    def get_type(self) -> ValueSourceType:
        return self.source_type

    def get_var(self):
        return self.var

    def get_define_insn(self) -> int:
        return self.define_insn


class ValueSourceSet(set, SSADataFlowState):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._too_big = False
        if len(self) > 100:
            self.clear()
            self._too_big = True
        if len(self) == 0:
            self._too_big = True

    def is_too_big(self):
        return self._too_big

    def set_too_big(self, too_big=True):
        self._too_big = too_big

    def __str__(self):
        super(set, self).__str__()


class ValueSourceAnalysis(SSADataFlowAnalysisBase):
    def meet(self, target_ssa_var: SSAVariable, *
             args: typing.Sequence[ValueSourceSet]) -> ValueSourceSet:
        for v in args:
            if v.is_too_big():
                return v
        retv = set()
        for v in args:
            retv |= v
        return ValueSourceSet(retv)

    def join(self, target_ssa_var: SSAVariable, *
             args: typing.Sequence[ValueSourceSet]) -> ValueSourceSet:
        for v in args:
            if v.is_too_big():
                continue
            else:
                retv = set(v)
                break
        else:
            return ValueSourceSet()

        for v in args:
            if v.is_too_big():
                continue
            retv &= v
        assert len(retv) > 0  # 不同来源的结果不没有任何交集？说明这个变量被def的地方根本没跑过？
        return ValueSourceSet(retv)

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self._equivalent_analysis: EquivalentAnalysis = fam.get_function_analysis(
            EquivalentAnalysis)

    def initialize(self, function: Function, fam: FunctionAnalysisManager):
        super().initialize(function, fam)
        self._use_def_analysis: SSAUseDefineAnalysis = fam.get_function_analysis(
            SSAUseDefineAnalysis)
        self._exp_tree_analysis: ExpTreeFunctionAnalysis = fam.get_function_analysis(
            ExpTreeFunctionAnalysis)
        self._fam = fam
        self._irfunc: MediumLevelILFunction = function.mlil.ssa_form

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        retv = super().run_on_function(function, fam)
        return retv

    def get_default_state(self, var: StandardSSAVariable) -> ValueSourceSet:
        return ValueSourceSet()

    def trans(self, inst: MediumLevelILInstruction) -> bool:

        if inst.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            d = self._irfunc.get_ssa_var_definition(inst.src)
            if d is None:
                name, idx = utils.base_tool.parse_arg_ssa(
                    self._irfunc, inst.src)
                if name is None or idx is None:
                    self.update_var_state(inst, ValueSourceSet())
                    return True
                    #raise RuntimeError('%s comes from where?' % inst.src)
                src = ParamValueSource(name, idx)
                self.update_var_state(inst, ValueSourceSet(set([src])))
                return True
            else:
                src_state = self.get_state_of(inst.src)
                self.update_var_state(inst, src_state)
            return True

        if inst.operation == MediumLevelILOperation.MLIL_ZX:
            self.update_var_state(inst, self.get_state_of(inst.src))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_SX:
            assert inst.size >= inst.src.size
            self.update_var_state(inst, self.get_state_of(inst.src))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
            module = self._fam.get_module()
            assert module.endianness in [
                Endianness.BigEndian, Endianness.LittleEndian]
            self.update_var_state(inst, self.get_state_of(inst.src))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_IMPORT:

            byte_sequence = analysis.utils.get_bytes_at(
                self._fam.get_module(), inst.constant, inst.size)
            if byte_sequence is None:
                return True
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

            src = ImportValueSource(
                ptr, self._exp_tree_analysis.get_root_insn(
                    inst.expr_index))
            self.update_var_state(inst, ValueSourceSet(set([src])))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            output_insn = inst.output
            bv: BinaryView = self._fam.get_module()
            size = bv.address_size
            idx = 0
            for p in output_insn.dest:
                new_state = ReturnValueSource(
                    idx,
                    size * idx,
                    size,
                    inst,
                    self._exp_tree_analysis.get_root_insn(
                        inst.expr_index))
                self.update_var_state(p, ValueSourceSet(set([new_state])))
                idx += 1
            return True

        if inst.operation == MediumLevelILOperation.MLIL_CONST:
            idx = self._exp_tree_analysis.get_root_insn(inst.expr_index)
            src = ConstIntValueSource(inst.constant, idx)
            self.update_var_state(inst, ValueSourceSet(set([src])))
            return True

        if inst.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            idx = self._exp_tree_analysis.get_root_insn(inst.expr_index)
            src = ConstPtrValueSource(inst.constant, idx)
            self.update_var_state(inst, ValueSourceSet(set([src])))
            return True
