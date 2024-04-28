from .helpers import load_test_module
import pytest
import unittest
from analysis.basic import ModuleAnalysisManager, Function
from analysis.equivalent_analysis import EquivalentAnalysis

import abc

import typing


def test_slow(subtests):
    module = load_test_module("./bash_a5753d33a0d4eb8f6ee894e5f70cff42")
    mam = ModuleAnalysisManager(module)
    for function in module.functions:
        with subtests.test(msg="Single Function", name=function.name):
            print(function.name)
            value_set: EquivalentAnalysis = mam.get_function_analysis(
                EquivalentAnalysis, function)
            assert value_set is not None
