from .helpers import load_test_module
import pytest
import unittest
from analysis.basic import ModuleAnalysisManager, Function
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation
from analysis.dataflow_analysis import StandardSSAVariable
from analysis.value_set_analysis import SimpleValueSetAnalysis, SimpleValueSet

import abc

import typing


@pytest.mark.parametrize("suffix",
                         ["i386-O0", "i386-O3",
                          "x86_64-O0", "x86_64-O3",
                          "mipsel-O0", "mipsel-O3",
                          "arm-O0", "arm-O3",
                          "mips-O0", "mips-O3",
                          "powerpc-O0", "powerpc-O3",
                          "aarch64-O0", "aarch64-O3"])
def test_simple_value_set(suffix):
    module = load_test_module(
        "./simple_value_set_exmaple_1/main" + "-" + suffix)
    mam = ModuleAnalysisManager(module)

    for function in module.functions:
        if function.name and function.name.startswith("main"):
            break
    else:
        assert False, "Cannot find main function"
        instructions = list(func.mlil.ssa_form.instructions)

    value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
        SimpleValueSetAnalysis, function)
    from analysis.use_define_analysis import SSAUseDefineAnalysis
    assert isinstance(value_set, SimpleValueSetAnalysis)

    instructions = list(function.mlil.ssa_form.instructions)

    calling_instruction = None
    for inst in instructions:
        if inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            callee_values = list(value_set.get_state_of(inst.dest))
            print(list(map(hex, callee_values)))
            if len(callee_values) != 1:
                continue
            callee_value = callee_values[0]
            symbol = module.get_symbol_at(callee_value)
            assert symbol is not None

            if symbol.name == "write":
                calling_instruction = inst
                break
    else:
        assert False, "Cannot find call instruction"

    calling_read = calling_instruction  # 第一个调用的函数是write
    count = calling_read.params[2]
    state = value_set.get_state_of(count)
    print(state)
    if suffix == "arm-O3":
        """ for this binary it contains such instructions
        movlt   r4, #0x26
        movge   r4, #0x64
        so r4 is either 0x26 or 0x64

        which is tranlated to

        r4#1 = phi(r4#0, 0x26)
        r4#2 = phi(r4#1, 0x64)

        and r4#0 is comes from initial value, which is not determined...
        """
        assert len(state) == 0
        return
    if "-O0" in suffix:
        assert 4 <= len(state) <= 4
        assert 2 in state
        assert 8 in state
        assert 38 in state
        assert 100 in state
    else:
        assert 2 <= len(state) <= 2
        assert 38 in state
        assert 100 in state


def test_slow(subtests):
    module = load_test_module("./bash_a5753d33a0d4eb8f6ee894e5f70cff42")
    mam = ModuleAnalysisManager(module)
    for function in module.functions:
        with subtests.test(msg="Single Function", name=function.name):
            print(function.name)
            value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
                SimpleValueSetAnalysis, function)
            assert value_set is not None


def test_slow_2(subtests):
    # this binary has an sx instruction
    module = load_test_module("./strange_binaries/rt2860v2_ap.ko")
    mam = ModuleAnalysisManager(module)
    for function in module.functions:
        with subtests.test(msg="Single Function", name=function.name):
            print(function.name)
            value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
                SimpleValueSetAnalysis, function)
            assert value_set is not None

def test_issue_6():
    module = load_test_module("./issues/6/chroot")
    mam = ModuleAnalysisManager(module)
    function = module.get_function_at(0x420bd8)
    assert function

    value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
        SimpleValueSetAnalysis, function)
def test_issue_7():
    module = load_test_module("./issues/7/smbd")
    mam = ModuleAnalysisManager(module)
    function = module.get_function_at(0x201880)
    assert function

    print(function.name)
    value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
        SimpleValueSetAnalysis, function)
    assert value_set is not None
