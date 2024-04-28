from .basic import CheckerBase
from ..basic import Function, Module, ModuleAnalysisManager
from ..value_set_analysis import SimpleValueSetAnalysis
from binaryninja.types import Symbol
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
import typing
from ..utils import get_call_ssa_instructions_to


class CurlEasySetoptChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "CurlEasySetopt"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        for inst in get_call_ssa_instructions_to(module, "curl_easy_setopt"):
            if inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                value_set: SimpleValueSetAnalysis = mam.get_function_analysis(
                    SimpleValueSetAnalysis, inst.function.source_function)
                if len(inst.params) < 3:
                    continue
                opts = list(value_set.get_state_of(inst.params[1]))
                values = list(value_set.get_state_of(inst.params[2]))

                if len(opts) != 1:
                    continue
                if len(values) != 1:
                    continue

                if opts[0] == 0x40 and values[0] == 0:
                    self.report(inst.function.source_function)
