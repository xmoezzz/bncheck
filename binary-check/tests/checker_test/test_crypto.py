from ..helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.srand_static_seed import SrandStaticSeedChecker
from analysis.checkers.crypto_ecb_mode import CryptoEcbModeChecker
from analysis.checkers.crypto_pbe_iteration import CryptoPBEFewerThan1000IterationsChecker
from analysis.checkers.crypto_static_iv import CryptoStaticIVChecker
from analysis.checkers.crypto_static_key import CryptoStaticKeyChecker
from analysis.checkers.crypto_static_salt import CryptoStaticSaltChecker

import pytest


@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_1(suffix):
    module: Module = load_test_module("./crypto_example/rand_seed_1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(SrandStaticSeedChecker)
    reports = check.get_reports()

    assert len(reports) == 1


def test_2():
    module: Module = load_test_module("./crypto_example/rand_seed/datalib")
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(SrandStaticSeedChecker)
    reports = check.get_reports()

    assert len(reports) == 1

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_3(suffix):
    module: Module = load_test_module("./crypto_example/ecb_mode/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(CryptoEcbModeChecker)
    reports = check.get_reports()

    assert len(reports) == 1

