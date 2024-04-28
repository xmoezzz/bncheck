from .helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager
from analysis.binary_info_analysis import BinaryInfoAnalysis
from analysis.binary_info_analysis import LibcType, PieType


class TestBinaryInfoAnalysis(unittest.TestCase):
    def setUp(self):
        self.module1 = load_test_module(
            "./bash_a5753d33a0d4eb8f6ee894e5f70cff42")
        self.mam1 = ModuleAnalysisManager(self.module1)
        self.binary_info_analysis1 = self.mam1.get_module_analysis(
            BinaryInfoAnalysis)

    def test_get_libc_type(self):
        assert self.binary_info_analysis1.get_libc_type() == LibcType.LIBC_GLIBC

    def test_get_pie_type(self):
        assert self.binary_info_analysis1.get_pie_type() == PieType.ENABLE
