from analysis.equivalent_analysis import EquivalentAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable


import typing

class Cpu64EquivalentAnalysis(EquivalentAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def pre_hook_on_inst(self, inst: MediumLevelILInstruction, helper_union) -> bool:
        if inst.operation in (
            MediumLevelILOperation.MLIL_SX,
            MediumLevelILOperation.MLIL_ZX,
            MediumLevelILOperation.MLIL_LOW_PART,
            MediumLevelILOperation.MLIL_VAR_SSA_FIELD
            ):
            helper_union(inst, inst.src)
        return False
    

