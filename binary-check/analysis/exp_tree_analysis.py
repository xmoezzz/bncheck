import binaryninja

from binaryninja import MediumLevelILInstruction
from analysis.basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, Module, FunctionAnalysis
import typing
import logging

logger = logging.getLogger(__name__)


class ExpTreeFunctionAnalysis(FunctionAnalysis):
    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self.cache = {}
        for blk in function.mlil.ssa_form:
            for insn in blk:

                """each IR instruction belongs to itself
                """
                self._trans(insn.expr_index, insn)

    def _trans(self, root_index: int, expr_insn: MediumLevelILInstruction):
        assert isinstance(expr_insn, MediumLevelILInstruction), "current type : %s" % (
            type(expr_insn))

        self.cache[expr_insn.expr_index] = root_index

        if hasattr(expr_insn, "left"):
            assert isinstance(expr_insn.left, MediumLevelILInstruction)
            self._trans(root_index, expr_insn.left)
        if hasattr(expr_insn, "right"):
            assert isinstance(expr_insn.right, MediumLevelILInstruction)
            self._trans(root_index, expr_insn.right)
        if hasattr(
                expr_insn,
                "src") and isinstance(
                expr_insn.src,
                MediumLevelILInstruction):
            self._trans(root_index, expr_insn.src)
        if hasattr(
                expr_insn,
                "dest") and isinstance(
                expr_insn.dest,
                MediumLevelILInstruction):
            self._trans(root_index, expr_insn.dest)
        if hasattr(expr_insn, "carry"):
            assert isinstance(expr_insn.carry, MediumLevelILInstruction)
            self._trans(root_index, expr_insn.carry)
        if hasattr(
                expr_insn,
                "output") and isinstance(
                expr_insn.output,
                MediumLevelILInstruction):
            self._trans(root_index, expr_insn.output)
        if hasattr(expr_insn, "params"):
            for p in expr_insn.params:
                self._trans(root_index, p)
        if hasattr(expr_insn, "stack"):
            self._trans(root_index, expr_insn.stack)
        if hasattr(expr_insn, "condition"):
            self._trans(root_index, expr_insn.condition)

    def get_root_insn(self, expr_index: int) -> int:
        if expr_index in self.cache:
            return self.cache[expr_index]
        return None
