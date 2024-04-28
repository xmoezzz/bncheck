from ..helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.signed_cmp import SignedCompareChecker

import pytest

@pytest.mark.parametrize("suffix",
        ["i386-O0"]) # FIXME: we have problem in x86-64
def test_1(suffix):
    module: Module = load_test_module("./signed_cmp/1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(SignedCompareChecker)
    reports = check.get_reports()

    bad_func_names = set()
    for var, func, func_name in reports:
        assert func_name.startswith("bad_")
        bad_func_names.add(func_name)
    assert len(bad_func_names) == 1

