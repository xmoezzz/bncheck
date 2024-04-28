from .helpers import load_test_module
import pytest
import unittest
from analysis.basic import ModuleAnalysisManager, Function, Module
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.free_function_detection_analysis import FreeFunctionDetectionAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable

import abc

import typing


def test_1(subtests):
    module = load_test_module("./free_function/1/main-x86_64-O0")
    mam = ModuleAnalysisManager(module)
    free_func_detect = mam.get_module_analysis(FreeFunctionDetectionAnalysis)

    for func in module.functions:
        print(func.name, hex(func.start))
        if func.name.startswith("main"):
            freed_something = False
            ssa_func = func.mlil.ssa_form
            for inst in ssa_func.instructions:
                if inst.operation in [
                        MediumLevelILOperation.MLIL_CALL_SSA,
                        MediumLevelILOperation.MLIL_TAILCALL_SSA]:
                    freed_something = freed_something or len(
                        free_func_detect.get_freed_arg_ssa_list(inst))

            assert freed_something
            break
    else:
        assert False, "cannot find main function?"
