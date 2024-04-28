from ..helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.uninitialized_var import UninitializedVarChecker

import pytest

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_1(suffix):
    module: Module = load_test_module("./uninitialized_var/1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(UninitializedVarChecker)
    reports = check.get_reports()

    assert len(reports) != 0

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_2(suffix):
    module: Module = load_test_module("./uninitialized_var/2/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(UninitializedVarChecker)
    reports = check.get_reports()

    assert len(reports) == 0