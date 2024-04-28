import enum
import subprocess
import re
import os
import logging
import tempfile
import typing
import queue

from .basic import FunctionAnalysis, AnalysisManager, Module, Function, FunctionAnalysisManager
from .use_define_analysis import SSAUseDefineAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from binaryninja.function import Variable
from collections import defaultdict
import abc


class DominatorTreeAnalysis(FunctionAnalysis):
    def initialize(self, function: Function, fam: FunctionAnalysisManager):
        super().initialize(function, fam)
        self.__fam = fam
        self.__use_def: SSAUseDefineAnalysis = fam.get_function_analysis(
            SSAUseDefineAnalysis)

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)
        self.__function = function
        self.__ssa = function.mlil.ssa_form
        assert self.__ssa

        self.__good = True
        for blk in self.__ssa:
            if blk.has_undetermined_outgoing_edges:
                self.__good = False
                break

    def does_dominate(
            self,
            dominator: MediumLevelILInstruction,
            dominatee: MediumLevelILInstruction,
            strict=False) -> typing.Optional[bool]:
        """
        返回dominator是否支配dominatee, 返回为None时表示不确定
        """
        assert dominator and dominatee
        assert isinstance(dominator, MediumLevelILInstruction)
        assert isinstance(dominatee, MediumLevelILInstruction)

        if not self.__good:
            return None

        dominator = self.__use_def.get_definition_instruction(dominator)
        dominatee = self.__use_def.get_definition_instruction(dominatee)
        if dominator is None or dominatee is None:
            return None
        assert dominator
        assert dominatee

        if dominatee.il_basic_block == dominator.il_basic_block:
            return dominator.expr_index < dominatee.expr_index or (
                dominator.expr_index == dominatee.expr_index and not strict)

        if dominator.il_basic_block in dominatee.il_basic_block.dominators:
            return True
        return False

    def does_post_dominate(
            self,
            dominator: MediumLevelILInstruction,
            dominatee: MediumLevelILInstruction,
            strict=False) -> typing.Optional[bool]:
        """
        返回dominator是否post_dominate dominatee, 返回为None时表示不确定
        """
        assert dominator and dominatee
        assert isinstance(dominator, MediumLevelILInstruction)
        assert isinstance(dominatee, MediumLevelILInstruction)

        if not self.__good:
            return None

        dominator = self.__use_def.get_definition_instruction(dominator)
        dominatee = self.__use_def.get_definition_instruction(dominatee)
        if dominator is None or dominatee is None:
            return None
        assert dominator
        assert dominatee

        if dominatee.il_basic_block == dominator.il_basic_block:
            return dominator.expr_index > dominatee.expr_index or (
                dominator.expr_index == dominatee.expr_index and not strict)  # 不要用address，因为，mips有delay slot

        if dominator.il_basic_block in dominatee.il_basic_block.post_dominators:
            return True
        return False
