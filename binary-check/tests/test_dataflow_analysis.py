from .helpers import load_test_module
import pytest
import unittest
from analysis.basic import ModuleAnalysisManager, Function
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from analysis.dataflow_analysis import StandardSSAVariable

import abc

import typing


class ValueSet(set, SSADataFlowState):
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


class SimpleValueSetAnalysis(SSADataFlowAnalysisBase):

    def meet(self, target_variable: SSAVariable, *
             args: typing.Sequence[ValueSet]) -> ValueSet:
        for v in args:
            if v.is_too_big():
                return v
        retv = set()
        for v in args:
            for vv in v:
                retv.add(vv)
        return ValueSet(retv)

    def join(self, target_ssa_var: SSAVariable, *
             args: typing.Sequence[ValueSet]) -> ValueSet:
        print(target_ssa_var, args)
        for v in args:
            if v.is_too_big():
                continue
            else:
                retv = set(v)
                break
        else:
            return ValueSet()

        for v in args:
            if v.is_too_big():
                continue
            retv &= v
        assert len(retv) > 0  # 不同来源的结果不没有任何交集？说明这个变量被def的地方根本没跑过？
        return ValueSet(retv)

    def get_default_state(self, var: StandardSSAVariable) -> ValueSet:
        return ValueSet()

    def trans(self, inst: MediumLevelILInstruction) -> bool:
        if inst.operation == MediumLevelILOperation.MLIL_ZX:
            self.update_var_state(inst, self.get_state_of(inst.src))
            return True
        if inst.operation == MediumLevelILOperation.MLIL_SX:
            self.update_var_state(inst, self.get_state_of(inst.src))
            return True
        if inst.operation == MediumLevelILOperation.MLIL_CONST:
            self.update_var_state(inst, ValueSet(set([inst.constant])))
            return True
        if inst.operation == MediumLevelILOperation.MLIL_MUL:
            for a in self.get_state_of(inst.left):
                for b in self.get_state_of(inst.right):
                    self.add_more_state(inst, ValueSet([a * b]))
            return True
        if inst.operation == MediumLevelILOperation.MLIL_ADD:
            s = set()
            for a in self.get_state_of(inst.left):
                for b in self.get_state_of(inst.right):
                    s.add(a + b)
            self.update_var_state(inst, ValueSet(s))
            return True
        if inst.operation == MediumLevelILOperation.MLIL_LSL:
            s = set()
            for a in self.get_state_of(inst.left):
                for b in self.get_state_of(inst.right):
                    s.add(a << b)
            self.update_var_state(inst, ValueSet(s))
            return True
        if inst.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
            self.update_var_state(inst, self.get_state_of(inst.src))
            return True


@pytest.mark.parametrize(
    "suffix", [
        "x86_64-O0", "x86_64-O3", "mipsel-O0", "mipsel-O3"])
def test_simple_value_set(suffix):
    module = load_test_module(
        "./simple_value_set_exmaple_1/main" + "-" + suffix)
    mam = ModuleAnalysisManager(module)
    for function in module.functions:
        if function.name and function.name.startswith("main"):
            break
    else:
        assert False, "Cannot find main function"

    instructions = list(function.mlil.ssa_form.instructions)

    value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
        SimpleValueSetAnalysis, function)
    assert isinstance(value_set, SimpleValueSetAnalysis)

    from analysis.use_define_analysis import SSAUseDefineAnalysis
    use_def = mam.get_function_analysis(SSAUseDefineAnalysis, function)
    print(use_def._users)
    for var in use_def.get_all_variables():
        if isinstance(var, MediumLevelILInstruction):
            print(var, value_set.get_state_of(var), var.operation)
        else:
            print(var, value_set.get_state_of(var))

    calling_instructions = []
    for inst in instructions:
        if inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            calling_instructions.append(inst)
    #assert len(calling_instructions) == 1, "源代码中main只调用了一次函数，是write"

    calling_read = calling_instructions[0]
    count = calling_read.params[2]
    state = value_set.get_state_of(count)
    print(count, state)
    if "-O0" in suffix:
        assert 2 in state
        assert 8 in state
        assert 38 in state
        assert 100 in state
        # 这里是因为有些等价的SSA表达式 s = a + b(但是其实a和b是同一个变量)
        assert 4 <= len(state) <= 8
    else:
        assert 2 <= len(state) <= 2
        assert 38 in state
        assert 100 in state


def test_slow(subtests):
    module = load_test_module("./bash_a5753d33a0d4eb8f6ee894e5f70cff42")
    mam = ModuleAnalysisManager(module)
    for function in module.functions:
        with subtests.test(msg="Single Function", name=function.name):
            value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
                SimpleValueSetAnalysis, function)
            assert value_set is not None
