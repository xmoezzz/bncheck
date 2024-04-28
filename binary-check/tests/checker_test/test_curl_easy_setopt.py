from ..helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.curl_easy_setopt import CurlEasySetoptChecker


def test_1():
    module: Module = load_test_module("./curl_verify_peer/1/fbwifi")
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)
    check = mam.get_module_analysis(CurlEasySetoptChecker)
    bad_functions = check.get_reports()
    assert len(bad_functions) == 1
    assert bad_functions[0].start == 0x25298


def test_2():
    module: Module = load_test_module("./curl_verify_peer/2/libws.so")
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)
    check = mam.get_module_analysis(CurlEasySetoptChecker)
    bad_functions = check.get_reports()
    assert len(bad_functions) == 1
    assert bad_functions[0].start == 0x1ca0


def test_3():
    module: Module = load_test_module("./curl_verify_peer/3/downloader")
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)
    check = mam.get_module_analysis(CurlEasySetoptChecker)
    bad_functions = check.get_reports()
    assert len(bad_functions) == 1
    assert bad_functions[0].start == 0xce88


def test_4():
    module: Module = load_test_module("./curl_verify_peer/4/ozker")
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)
    check = mam.get_module_analysis(CurlEasySetoptChecker)
    bad_functions = check.get_reports()
    assert len(bad_functions) == 0
