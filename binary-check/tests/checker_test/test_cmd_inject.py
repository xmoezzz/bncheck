from ..helpers import load_test_module
import unittest
from prologue.prologue_main import PrologueManager
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.cmd_inject import CmdInjectChecker

import pytest

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_1(suffix):
    module: Module = load_test_module("./cmd_inject/1/main-" + suffix)
    pp : PrologueManager = PrologueManager(module)
    pp.on_start()
    module = pp.on_end()
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(CmdInjectChecker)
    reports = check.get_reports()
    assert len(reports) == 2



@pytest.mark.parametrize("path",
                         ["cmd_inject/real_bugs/cgibin",
                          "cmd_inject/real_bugs/httpd",
                          "cmd_inject/real_bugs/stimg.cgi"
                          ])
def test_slow_realworld_bug_1(path):
    module: Module = load_test_module(path)
    pp : PrologueManager = PrologueManager(module)
    pp.on_start()
    module = pp.on_end()
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)
    check = mam.get_module_analysis(CmdInjectChecker)
    reports = check.get_reports()
    for rp in reports:
        print(rp)

    assert len(reports) != 0

