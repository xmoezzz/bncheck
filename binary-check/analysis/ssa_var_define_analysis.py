import binaryninja

from analysis.basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, Module, FunctionAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable, MediumLevelILFunction
from binaryninja import Endianness, BinaryView


class SSAVarDefineAnalysis(FunctionAnalysis):

    def initialize(self, function: Function, fam: FunctionAnalysisManager):
        super().initialize(function, fam)

        self._function: Function = function
        self._irfunc: MediumLevelILFunction = function.mlil.ssa_form
        self._module: Module = fam.get_module()
        self._use_define_analysis: SSAUseDefineAnalysis = fam.get_function_analysis(
            SSAUseDefineAnalysis)

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)

        variables = self._use_define_analysis.get_all_variables()
        for v in variables:
            if not isinstance(v, SSAVariable):
                continue
            d = self._irfunc.get_ssa_var_definition(v):
            if d is not None:
