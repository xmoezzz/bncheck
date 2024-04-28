from binaryninja import MediumLevelILInstruction, MediumLevelILOperation
from analysis.basic import Module, Function

import typing

def strip(name):
    if name.startswith("class ") and name.endswith("`RTTI Type Descriptor'"):
        return name[6:-23]
    elif name.startswith("struct ") and name.endswith("`RTTI Type Descriptor'"):
        return name[7:-23]
    else:
        return name


class RTTIStruc(object):
    tid = 0
    struc = 0
    size = 0




