import enum
import subprocess
import re
import os
import logging
import tempfile
import typing
import utils.graph_dfs

from queue import Queue
from binaryninja import MediumLevelILFunction, MediumLevelILInstruction, MediumLevelILBasicBlock

from .basic import FunctionAnalysis, AnalysisManager, Module, Function, FunctionAnalysisManager


class IRNode(object):
    """basic block for each IR

    Arguments:
        object {[type]} -- [description]

    Returns:
        [type] -- [description]
    """

    def __init__(
            self,
            ir: MediumLevelILInstruction,
            blk: MediumLevelILBasicBlock):
        self.ir = ir
        self.blk = blk
        self.incoming_edges = set()
        self.outgoing_edges = set()

    def __hash__(self):
        return hash(self.ir.expr_index)

    def __eq__(self, other):
        assert isinstance(other, IRNode)
        return self.ir.expr_index == other.expr_index

    def add_incoming_edges(self, node):
        assert isinstance(node, IRNode)

        if node not in self.incoming_edges:
            self.incoming_edges.add(node)

    def add_outgoing_edges(self, node):
        assert isinstance(node, IRNode)

        if node not in self.outgoing_edges:
            self.outgoing_edges.add(node)

    def get_blk(self) -> MediumLevelILBasicBlock:
        return self.blk

    def in_incoming_edges(self, node) -> bool:
        assert isinstance(node, IRNode)
        return node in self.incoming_edges

    def in_outgoing_edges(self, node) -> bool:
        assert isinstance(node, IRNode)
        return node in self.outgoing_edges

    def get_incoming_edges(self) -> list:
        return list(self.incoming_edges)

    def get_outgoing_edges(self) -> list:
        return list(self.outgoing_edges)


class IRBasicBlockAnalysis(FunctionAnalysis):
    """split IR basic block

    Arguments:
        FunctionAnalysis {[type]} -- [description]
    """

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        self._module: Module = fam.get_module()
        self._irfunc: MediumLevelILFunction = function.mlil.ssa_form
        self._start_blk: MediumLevelILBasicBlock = None
        self._end_blks = set()
        self._start = None
        self._ends = list()
        self._cache: typing.Dict[int, IRNode] = dict()
        self._path = list()
        self._g: utils.graph_dfs.GraphDfs = None
        self._max_index = None
        blks = []
        for blk in self._irfunc:
            blk_insn = []
            for insn in blk:
                node = IRNode(insn, blk)
                self._cache[insn.expr_index] = node
                blk_insn.append(insn)
            blks.append(blk_insn)

        for blk_insn in blks:
            last_insn = None
            for i in range(0, len(blk_insn)):
                # bn在这里可能会出错
                blk = self._cache[blk_insn[i].expr_index].blk
                if last_insn is None:
                    for incoming_blk in blk.incoming_edges:
                        incoming_insn = self._get_blk_last_insn(
                            incoming_blk.source)
                        self._cache[blk_insn[i].expr_index].add_incoming_edges(
                            self._cache[incoming_insn.expr_index])
                    if len(blk_insn) != 1:
                        assert i != len(blk_insn) - 1
                        self._cache[blk_insn[i].expr_index].add_outgoing_edges(
                            self._cache[blk_insn[i + 1].expr_index])

                if i == len(blk_insn) - 1:
                    for outgoing_blk in blk.outgoing_edges:
                        outgoing_insn = self._get_blk_first_insn(
                            outgoing_blk.target)
                        self._cache[blk_insn[i].expr_index].add_outgoing_edges(
                            self._cache[outgoing_insn.expr_index])
                    if len(blk_insn) != 1:
                        assert last_insn is not None
                        self._cache[blk_insn[i].expr_index].add_incoming_edges(
                            self._cache[last_insn.expr_index])
                    break

                if last_insn is not None and i != len(blk_insn) - 1:
                    assert last_insn is not None
                    self._cache[blk_insn[i].expr_index].add_incoming_edges(
                        self._cache[last_insn.expr_index])
                    self._cache[blk_insn[i].expr_index].add_outgoing_edges(
                        self._cache[blk_insn[i + 1].expr_index])

                last_insn = blk_insn[i]

    def _get_start_blk(self):
        if self._start_blk:
            return self._start_blk
        for blk in self._irfunc:
            if len(blk.incoming_edges) == 0:
                self._start_blk = blk
                return self._start_blk

        raise RuntimeError("cannot find start blk")

    def _get_end_blks(self):
        if len(self._end_blks):
            return self._end_blks
        for blk in self._irfunc:
            if len(blk.outgoing_edges) == 0:
                self._end_blks.add(blk)
                return self._end_blks

        assert len(blk.outgoing_edges)

    def _get_blk_last_insn(self, blk: MediumLevelILBasicBlock):
        insn = None
        for _insn in blk:
            insn = _insn
        return insn

    def _get_blk_first_insn(self, blk: MediumLevelILBasicBlock):
        for insn in blk:
            return insn

    def get_ends(self):
        if len(self._ends) == 0:
            for k, v in self._cache.items():
                if len(v.get_outgoing_edges()) == 0:
                    self._ends.append(v)
            assert len(self._ends) != 0
            return self._ends
        else:
            return self._ends

    def get_entry(self):
        if self._start is None:
            for k, v in self._cache.items():
                if len(v.get_incoming_edges()) == 0:
                    self._start = v
                    return self._start
            raise RuntimeError("Unable to find the entry basic block")
        else:
            return self._start

    def get_ir_blk_count(self):
        return len(self._cache)

    def get_max_index(self):
        if self._max_index is None:
            idx = 0
            for k, v in self._cache.items():
                if k > idx:
                    idx = k
            self._max_index = idx

        return self._max_index

    def get_ir_node_at(self, expr_index: int):
        if expr_index in self._cache:
            return self._cache[expr_index]
        return None

    def __create_graph(self):
        assert self._g is None

        g: utils.graph_dfs.GraphDfs = utils.graph_dfs.GraphDfs(
            self.get_max_index() + 1)
        for k, v in self._cache.items():
            for node in v.get_outgoing_edges():
                g.add_edge(k, node.ir.expr_index)
        self._g = g

    def get_one_possible_path(self):
        """from start to end
        """
        if len(self._path) == 0:
            if self._g is None:
                self.__create_graph()

            self._g.reset_result()
            ends = self.get_ends()

            self._g.find_one_path(
                self.get_entry().ir.expr_index,
                ends[0].ir.expr_index)
            self._path = self._g.get_result()
            self._g.reset_result()

        return self._path

    def get_path(self, start, end):
        assert start in self._cache
        assert end in self._cache

        results = []
        self._g.reset_result()
        self._g.find_all_path(start, end)
        results = self._g.get_result()
        self._g.reset_result()
        return results
