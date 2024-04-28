import unittest
from analysis.basic import ModuleAnalysisManager, Module, Function
from analysis.checkers.srand_static_seed import SrandStaticSeedChecker
from analysis.checkers.crypto_ecb_mode import CryptoEcbModeChecker
from analysis.checkers.crypto_pbe_iteration import CryptoPBEFewerThan1000IterationsChecker
from analysis.checkers.crypto_static_iv import CryptoStaticIVChecker
from analysis.checkers.crypto_static_key import CryptoStaticKeyChecker
from analysis.checkers.crypto_static_salt import CryptoStaticSaltChecker
from analysis.checkers.unchecked_malloc import UncheckedMallocChecker
from analysis.checkers.cmd_inject import CmdInjectChecker
from analysis.checkers.signed_var import SignedVarChecker
from analysis.checkers.uninitialized_var import UninitializedVarChecker

from prologue.prologue_main import PrologueManager
import pprint
import os
import sys

from binaryninja import BinaryViewType

def test(filename: str, tag : str):
    print('checking : ', filename)
    module = None
    if filename.endswith('.bndb'):
        module = BinaryViewType.get_view_of_file(filename)
        module.update_analysis_and_wait()
    else:
        bndb_filename : str = filename + '.bndb'
        if os.path.exists(bndb_filename):
            module = BinaryViewType.get_view_of_file(filename)
            module.update_analysis_and_wait()
        else:
            module = BinaryViewType["ELF"].open(filename)
            module.update_analysis_and_wait()
            module.create_database(bndb_filename)
    
    assert not module is None
    prologue = PrologueManager(module)
    prologue.on_start()
    module = prologue.on_end()

    mam = ModuleAnalysisManager(module)
    checker = None
    if tag == 'iv':
        checker : CryptoStaticIVChecker = mam.get_module_analysis(CryptoStaticIVChecker, module)
    elif tag == 'srand':
        checker : SrandStaticSeedChecker = mam.get_module_analysis(SrandStaticSeedChecker, module)
    elif tag == 'key':
        checker : CryptoStaticKeyChecker = mam.get_module_analysis(CryptoStaticKeyChecker, module)
    elif tag == 'ecb':
        checker : CryptoEcbModeChecker = mam.get_module_analysis(CryptoEcbModeChecker, module)
    elif tag == 'pbe':
        checker : CryptoPBEFewerThan1000IterationsChecker = mam.get_module_analysis(CryptoPBEFewerThan1000IterationsChecker, module)
    elif tag == 'salt':
        checker : CryptoStaticSaltChecker = mam.get_module_analysis(CryptoStaticSaltChecker, module)
    elif tag == 'malloc':
        checker : UncheckedMallocChecker = mam.get_module_analysis(UncheckedMallocChecker, module)
    elif tag == 'sign':
        checker : SignedVarChecker = mam.get_module_analysis(SignedVarChecker, module)
    elif tag == 'cmd':
        checker : CmdInjectChecker = mam.get_module_analysis(CmdInjectChecker, module)
    elif tag == 'uninit':
        checker : UninitializedVarChecker = mam.get_module_analysis(UninitializedVarChecker, module)
    elif tag == 'malloc':
        checker : UncheckedMallocChecker = mam.get_module_analysis(UncheckedMallocChecker, module)
    else:
        raise RuntimeError('unknown tag : %s' % tag)
    
    rps = checker.get_reports()
    if len(rps):
        print('========================')
        print("path : %s" % module._file.filename)
        for rp in rps:
            print(rp)
        print('========================')


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(-1)
    test(sys.argv[1], sys.argv[2])

