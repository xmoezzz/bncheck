import binaryninja

from analysis.basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, Module, FunctionAnalysis
from analysis.dataflow_analysis import SSADataFlowAnalysisBase, SSADataFlowState
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable, MediumLevelILFunction
from binaryninja import Endianness, BinaryView
from analysis.dataflow_analysis import StandardSSAVariable
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis
from analysis.exp_tree_analysis import ExpTreeFunctionAnalysis
from analysis.value_source_analysis import ValueSourceAnalysis, ValueSourceType, ParamValueSource, ReturnValueSource, ConstIntValueSource, \
    ConstPtrValueSource, ImportValueSource, UnknownValueSource

import utils.base_tool
import logging
import enum


class StructSource(object):
    def __init__(self, source: list, size: int):
        self.source = source
        self.size = size


class StructSourceKey(object):
    def __init__(self, expr_index, var, size):
        self.id = "%s_%s_%s" % (expr_index, var, size)

    def hash(self):
        return hash(self.id)


class StructItemType(enum.IntEnum):
    ITEM_TYPE = 0,
    PADDING_TYPE = 1


class StructItem(object):
    def __init__(self, item_type, size):
        self.item_type = item_type
        self.size = size


class StructLayout(object):
    def __init__(self, size):
        self.layout = list()
        self.size = size

    def push_item(self, size):
        item = StructItem(StructItemType.ITEM_TYPE, size)
        self.layout.append(item)

    def push_padding(self, size):
        item = StructItem(StructItemType.PADDING_TYPE, size)
        self.layout.append(item)

    def __iter__(self):
        for item in self.layout:
            yield item

    def validate_size(self):
        _size = 0
        for item in self.layout:
            _size += item.size
        return _size == self.size


class StructSourceException(Exception):
    pass


class StructSourceAnalysis(FunctionAnalysis):

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self._value_source_analysis: ValueSourceAnalysis = fam.get_function_analysis(
            ValueSourceAnalysis)
        self._exp_tree_analysis: ExpTreeFunctionAnalysis = fam.get_function_analysis(
            ExpTreeFunctionAnalysis)
        self._fam = fam
        self._func: Function = function
        self._struct_cache = {}

    def get_stucture_at(self, expr_index: int, var, layout: StructLayout):
        key = StructSourceKey(expr_index, var, layout.size)
        if key in self._struct_cache:
            return self._struct_cache[key]

        value = self._sync_analysis(expr_index, var, layout)
        self._struct_cache[key] = value
        return value

    def _sync_analysis(
            self,
            expr_index: int,
            var,
            layout: StructLayout) -> StructSourceKey:
        assert isinstance(var, SSAVariable)

        current_var = utils.base_tool.calcNext(var, self._func)
