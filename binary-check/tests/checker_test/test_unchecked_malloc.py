from ..helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.unchecked_malloc import UncheckedMallocChecker

import pytest

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_1(suffix):
    module: Module = load_test_module("./unchecked_malloc/1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(UncheckedMallocChecker)
    reports = check.get_reports()

    assert len(reports) != 0

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_2_no_bug(suffix):
    module: Module = load_test_module("./unchecked_malloc/2/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(UncheckedMallocChecker)
    reports = check.get_reports()

    assert len(reports) == 0


