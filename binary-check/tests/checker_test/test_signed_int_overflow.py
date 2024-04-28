from ..helpers import load_test_module, load_test_module_dir
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.signed_var import SignedVarChecker

import pytest

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_1(suffix):
    module: Module = load_test_module("./int_overflow/1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(SignedVarChecker)
    reports = check.get_reports()

    assert len(reports) == 1


@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_2(suffix):
    module: Module = load_test_module("./int_overflow/1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(SignedVarChecker)
    reports = check.get_reports()

    assert len(reports) == 1


