from .helpers import load_test_module
import pytest
import unittest
from analysis.basic import ModuleAnalysisManager, Function
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation
from analysis.dataflow_analysis import StandardSSAVariable
from analysis.value_source_analysis import ValueSourceAnalysis

import abc

import typing


def test_slow(subtests):
    module = load_test_module("./bash_a5753d33a0d4eb8f6ee894e5f70cff42")
    mam = ModuleAnalysisManager(module)
    for function in module.functions:
        with subtests.test(msg="Single Function", name=function.name):
            print(function.name)
            value_source: ValueSourceAnalysis = mam.get_function_analysis(
                ValueSourceAnalysis, function)
            assert value_source is not None
