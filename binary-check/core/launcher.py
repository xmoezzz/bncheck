from analysis.basic import Function, Module, FunctionAnalysis, FunctionAnalysisManager, \
    ModuleAnalysis, ModuleAnalysisManager


##prologue
from prologue.basic import PrologueAnalysis
from prologue.prologue_main import PrologueManager

##analysis.check
from analysis.checkers.buffer_overflow import BufferOverflowChecker
from analysis.checkers.cmd_inject import CmdInjectChecker
from analysis.checkers.content_len_unchecked import ContentLenUncheckedChecker
from analysis.checkers.crypto_ecb_mode import CryptoEcbModeChecker
from analysis.checkers.crypto_pbe_iteration import CryptoPBEFewerThan1000IterationsChecker
from analysis.checkers.crypto_static_iv import CryptoStaticIVChecker
from analysis.checkers.crypto_static_key import CryptoStaticKeyChecker
from analysis.checkers.crypto_static_salt import CryptoStaticSaltChecker
from analysis.checkers.curl_easy_setopt import CurlEasySetoptChecker
from analysis.checkers.div_zero import DivZeroChecker
from analysis.checkers.password_backdoor import PasswordBackdoorChecker
from analysis.checkers.signed_var import SignedVarChecker
from analysis.checkers.srand_static_seed import SrandStaticSeedChecker
from analysis.checkers.unchecked_malloc import UncheckedMallocChecker
from analysis.checkers.uninitialized_var import UninitializedVarChecker
from analysis.checkers.url_filter import UrlFilterChecker
from analysis.checkers.use_after_free import UseAfterFreeChecker

from analysis.module_info_analysis import ModuleInfoAnalysis

from tests.helpers import load_test_module_file

import binaryninja
import typing
import logging
import json
import pprint
import tqdm
import os

logger = logging.getLogger(__file__)


class Launcher(object):
    def __init__(self, filename : str, version_scan_filename : str, output_name : str):
        self.__is_bndb : bool = filename.endswith(".bndb")
        self.__module : Module = load_test_module_file(filename)
        self.__pre_init(self.__module)
        
        self.__mam : ModuleAnalysisManager = ModuleAnalysisManager(self.__module)
        self.__reports = dict()
        self.__output_name = output_name
        success = False
        if isinstance(version_scan_filename, str) and os.path.isfile(version_scan_filename):
            
            try:
                with open(version_scan_filename, 'r') as fd:
                    data = json.load(fd)
                    module_info : ModuleInfoAnalysis = self.__mam.get_module_analysis(ModuleInfoAnalysis, self.__module)
                    module_info.init_by_version_scan_data(data)
                    success = True
            except Exception as e:
                logger.warn("error => %s" % e)
        
        if success:
            module_info : ModuleInfoAnalysis = self.__mam.get_module_analysis(ModuleInfoAnalysis, self.__module)
            if not module_info.is_built_in():
                logger.warning("built-in version is disabled")
            try:
                module_info.init_by_running_version_scan(filename)
            except:
                pass
            

        """TODO : import data from version-scan
        """
    
    def __pre_init(self, module : Module):
        prologue = PrologueManager(module)
        prologue.on_start()
        prologue.on_start()

    def check(self):
        checker_classes = []
        checker_classes.append(BufferOverflowChecker)
        checker_classes.append(CmdInjectChecker)
        checker_classes.append(ContentLenUncheckedChecker)
        checker_classes.append(CryptoEcbModeChecker)
        checker_classes.append(CryptoPBEFewerThan1000IterationsChecker)
        checker_classes.append(CryptoStaticIVChecker)
        checker_classes.append(CryptoStaticKeyChecker)
        checker_classes.append(CryptoStaticSaltChecker)
        checker_classes.append(CurlEasySetoptChecker)
        checker_classes.append(DivZeroChecker)
        checker_classes.append(PasswordBackdoorChecker)
        checker_classes.append(SignedVarChecker)
        checker_classes.append(SrandStaticSeedChecker)
        checker_classes.append(UncheckedMallocChecker)
        checker_classes.append(UninitializedVarChecker)
        checker_classes.append(UrlFilterChecker)
        checker_classes.append(UseAfterFreeChecker)

        bar = tqdm.tqdm(checker_classes)
        for checker_class in bar:
            bar.set_description("Processing checker : %s" % checker_class.get_checker_name())
            checker = self.__mam.get_module_analysis(checker_class, self.__module)
            issues = checker.get_reports()
            if len(issues):
                self.__push_report(checker.get_checker_name(), issues)
        

    def __push_report(self, tag : str, issues : list)->bool:
        if tag in self.__reports:
            return False
        if issues is None or len(issues) == 0:
            return False
        
        self.__reports[tag] = issues
        return True
        

    def generate_report(self)->bool:
        if self.__output_name in ("stdout", "stderr"):
            pprint.pprint(self.__reports)
        else:
            try:
                with open(self.__output_name, "r") as fd:
                    json.dump(self.__reports, fd, indent=4)
            except Exception as e:
                logger.error("failed to save to file : %s" % str(e))
                return False
        
        return True

