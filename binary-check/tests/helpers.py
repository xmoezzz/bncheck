from analysis.basic import Module, AnalysisManager
from binaryninja import BinaryViewType, BinaryView
import os
from elftools.elf.elffile import ELFFile


def scan_dir(root: str):
    for (dirpath, dirnames, filenames) in os.walk(root):
        for file in filenames:
            yield os.path.join(dirpath, file)

def is_elf_file(path: str)->bool:
    try:
        with open(path, "rb") as fd:
            elf = ELFFile(fd)
    except Exception:
        return False
    return True

def load_test_module_dir(path: str) -> Module:
    assert os.path.exists(path)
    assert os.path.isdir(path)
    for filepath in scan_dir(path):
        if not is_elf_file(filepath):
            continue
        
        module = BinaryViewType["ELF"].open(filepath)
        module.update_analysis_and_wait()
        yield module


def load_test_module_file(path: str) -> Module:
    """
    load module for the test binary
    """
    fullpath = path
    assert os.path.isfile(fullpath)

    assert not path.endswith(".bndb")

    bndb_path = fullpath + ".bndb"
    if os.path.exists(bndb_path):
        module = BinaryViewType.get_view_of_file(bndb_path)
        module.update_analysis_and_wait()
    else:
        module = BinaryViewType["ELF"].open(fullpath)
        module.update_analysis_and_wait()
        module.create_database(bndb_path)

    assert module is not None

    return module

def load_test_module(path: str) -> Module:
    """
    load module for the test binary
    """
    root_dir = os.path.abspath(os.path.dirname(__file__))
    fullpath = os.path.join(root_dir, "blob", path)
    assert os.path.exists(fullpath)
    assert os.path.isfile(fullpath)

    assert not path.endswith(".bndb")

    bndb_path = fullpath + ".bndb"
    if os.path.exists(bndb_path):
        module = BinaryViewType.get_view_of_file(bndb_path)
        module.update_analysis_and_wait()
    else:
        module = BinaryViewType["ELF"].open(fullpath)
        module.update_analysis_and_wait()
        module.create_database(bndb_path)

    assert module is not None

    return module
