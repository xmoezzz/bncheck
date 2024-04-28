from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.module_info_analysis import ModuleInfoAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.value_set_analysis import SimpleValueSetAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.return_var_analysis import ReturnVarAnalysis
from analysis.utils import get_call_ssa_instructions_to

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation, \
    SSAVariable, Variable, Type
from utils.base_tool import safe_str, get_callee_name

import binaryninja
import typing
import logging
import enum
import copy
import abc


class CallChainItem(object):
    def __init__(self, func : Function, insn : MediumLevelILInstruction, target_index : int):
        assert isinstance(func, Function)
        assert isinstance(insn, MediumLevelILInstruction)
        self.func : Function = func
        self.insn : MediumLevelILInstruction = insn
        self.target_index : int = target_index
    
    @property
    def index(self)->int:
        return self.target_index
    
    @property
    def instruction(self)->MediumLevelILInstruction:
        return self.insn


class CryptoReportItemBase(object):
    def __init__(self, chain : typing.List[CallChainItem] = None, desc : str = None):
        self.chain : typing.List[CallChainItem] = list()
        if not chain is None:
            assert isinstance(chain, list)
            self.chain = chain
        self.desc = desc
    
    def push(self, func : Function, insn : MediumLevelILInstruction, index : int):
        assert isinstance(func, Function)
        assert isinstance(insn, MediumLevelILInstruction)
        assert isinstance(index, int)
        item = CallChainItem(func, insn, index)
        self.chain.append(item)
    
    def set_desc(self, desc : str):
        self.desc = desc
    

        
        
