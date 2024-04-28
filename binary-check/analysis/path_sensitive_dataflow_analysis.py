from analysis.basic import FunctionAnalysisManager, Function, FunctionAnalysis
from analysis.use_define_analysis import KeyedDict
from analysis.ir_blk_analysis import IRBasicBlockAnalysis
from binaryninja import SSAVariable, MediumLevelILInstruction, MediumLevelILOperation

import abc
import logging


class SSAPathSensitiveDataFlowBase(FunctionAnalysis, abc.ABC):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__states = KeyedDict(lambda x: self.get_default_state(x))

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self.__function: Function = function
        self.__ir_blk_analysis: IRBasicBlockAnalysis = fam.get_function_analysis()

    def get_default_state(self):
        pass
