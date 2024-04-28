from __future__ import print_function
import os
import sys
import logging
import argparse

logging.basicConfig()
logger = logging.getLogger()

try:
    import binaryninja
except ImportError:
    logger.error("unable to import binaryninja, pls install it:)")
    sys.exit()

from core.launcher import Launcher

def ExecuteBinaryCheck(binary_name : str, version_scan_name : str, output : str):
    launcher = Launcher(binary_name, version_scan_name, output)
    launcher.check()
    launcher.generate_report()


if __name__ == '__main__':
    parse = argparse.ArgumentParser(description='BinaryChecker')
    parse.add_argument('-i', '--input',  type=str, default='',       help='input file', required=True)
    parse.add_argument('-o', '--output', type=str, default='stdout', help='output')
    parse.add_argument('-s', '--vs',     type=str, default=None,     help='version-scan json data')

    p = parse.parse_args()
    
    input_file = p.input
    if os.path.isfile(input_file) == False:
        logger.error('unable to open input file %s' % (input_file))
        sys.exit(-1)
    
    launcher = Launcher(input_file, p.vs, p.output)
    launcher.check()
    launcher.generate_report()
    
    