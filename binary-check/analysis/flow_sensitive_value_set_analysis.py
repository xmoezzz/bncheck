from analysis.basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, Module
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from analysis.dataflow_analysis import StandardSSAVariable
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis

from binaryninja.enums import Endianness

import abc

import typing
from contextlib import contextmanager

from . import utils


class FlowSensitiveValueSetAnalysis(SSADataFlowAnalysisBase):
    def run_on_function(self, )
