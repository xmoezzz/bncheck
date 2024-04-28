import binaryninja
import typing

from binaryninja import MediumLevelILOperation, MediumLevelILInstruction
from analysis.basic import FunctionAnalysis, AnalysisManager, Function, FunctionAnalysisManager
from utils.base_tool import get_callee_name


class IRCallInfo(object):
    def __init__(self, insn, name):
        self.insn = insn
        self.name = name


class IRCallsAnalysis(FunctionAnalysis):

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self.calls = []
        self.callinfos = []

        assert function.mlil.ssa_form

        for blk in function.mlil.ssa_form:
            for insn in blk:
                if insn.operation not in (
                        MediumLevelILOperation.MLIL_CALL,
                        MediumLevelILOperation.MLIL_CALL_UNTYPED,
                        MediumLevelILOperation.MLIL_TAILCALL,
                        MediumLevelILOperation.MLIL_TAILCALL_UNTYPED):
                    continue

                self.calls.append(insn)
                self.callinfos.append(
                    IRCallInfo(
                        insn, get_callee_name(
                            function.bv, insn)))

    def get_ir_calls(self) -> list:
        return self.calls

    def get_ir_callinfos(self) -> list:
        return self.callinfos
