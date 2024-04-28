from analysis.basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, FunctionAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable

import typing

class ReturnVarAnalysis(FunctionAnalysis):
    def run_on_function(self, function: Function, fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)
        self.__retv : typing.Dict[SSAVariable, MediumLevelILInstruction] = dict()
        for blk in function.mlil.ssa_form:
            for insn in blk:
                if insn.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                   for v in insn.output.dest:
                       self.__retv[v] = insn 
    
    def get_return_vars_to_insn(self)->typing.Dict[SSAVariable, MediumLevelILInstruction]:
        return self.__retv
    
    def get_return_vars(self)->typing.List[SSAVariable]:
        return self.__retv.keys()



