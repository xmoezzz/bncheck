from .helpers import load_test_module
import pytest
import unittest
from analysis.basic import ModuleAnalysisManager, Function
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation
from analysis.dataflow_analysis import StandardSSAVariable
from analysis.ir_blk_analysis import IRBasicBlockAnalysis

import abc

import typing


def test_slow(subtests):
    module = load_test_module("./bash_a5753d33a0d4eb8f6ee894e5f70cff42")
    mam = ModuleAnalysisManager(module)
    for function in module.functions:
        with subtests.test(msg="Single Function", name=function.name):
            print(function.name)
            ir_blk: IRBasicBlockAnalysis = mam.get_function_analysis(
                IRBasicBlockAnalysis, function)
            assert ir_blk is not None
            entry = ir_blk.get_entry()
            ends = ir_blk.get_ends()
