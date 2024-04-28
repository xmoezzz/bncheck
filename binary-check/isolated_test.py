from  tests.helpers import load_test_module, load_test_module_dir
import unittest
from analysis.basic import ModuleAnalysisManager, Module, Function
from analysis.checkers.crypto_ecb_mode import CryptoEcbModeChecker
from utils.base_tool import get_callee_name
import pprint
import os
import sys
import subprocess

def scan_dir(root: str):
    for (dirpath, dirnames, filenames) in os.walk(root):
        for file in filenames:
            yield os.path.join(dirpath, file)

def test(tag : str):
    for module_file in scan_dir("/mnt/d/binary-check-tests/" + tag + "/bndb"):
        p = subprocess.Popen(["python3", "./isolated_test_sub.py", module_file, tag])
        p.wait()

def test_dir(dir_path : str, tag : str):
    for module_file in scan_dir(dir_path):
        p = subprocess.Popen(["python3", "./isolated_test_sub.py", module_file, tag])
        p.wait()

def test_file(file_path : str, tag : str):
    p = subprocess.Popen(["python3", "./isolated_test_sub.py", file_path, tag])
    p.wait()

if __name__ == '__main__':
    if len(sys.argv) > 2:
        if os.path.isdir(sys.argv[2]):
            test_dir(sys.argv[2], sys.argv[1])
        elif os.path.isfile(sys.argv[2]):
            test_file(sys.argv[2], sys.argv[1])
    else:
        test(sys.argv[1])
