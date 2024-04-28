from ..helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.buffer_overflow import BufferOverflowChecker

import pytest

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_1(suffix):
    module: Module = load_test_module("./buffer_overflow/1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(BufferOverflowChecker)
    reports = check.get_reports()

    bad_func_names = set()
    for inst, source in reports:
        print(inst, source)
        assert inst.function.source_function.name.startswith("bug_")
        bad_func_names.add(inst.function.source_function.name)
    assert len(bad_func_names) == 4

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_2(suffix):
    module: Module = load_test_module("./buffer_overflow/2/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(BufferOverflowChecker)
    reports = check.get_reports()

    bad_func_names = set()
    for inst, source in reports:
        print(inst, source)
        assert inst.function.source_function.name.startswith("bug_")
        bad_func_names.add(inst.function.source_function.name)
    assert len(bad_func_names) == 2


@pytest.mark.parametrize("path",
                         ["curl_verify_peer/1/fbwifi",
                          "curl_verify_peer/2/libws.so",
                          "curl_verify_peer/4/ozker",
                          ])
def test_slow_no_bug_on_some_big_binaries(path):
    module: Module = load_test_module(path)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)
    check = mam.get_module_analysis(BufferOverflowChecker)
    reports = check.get_reports()
    bad_func_names = set()
    for inst, source in reports:
        print(inst, source, inst.function.source_function.name)

    assert len(reports) == 0


def test_slow_realworld_bug_1():
    module: Module = load_test_module("buffer_overflow/real_bug_1/busybox")
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)
    check = mam.get_module_analysis(BufferOverflowChecker)
    reports = check.get_reports()

    for inst, source in reports:
        print(inst, inst.function.source_function.name)

    assert len(reports) == 1
    assert reports[0][0].function.source_function.start == 0x004151C4
