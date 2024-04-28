from .basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, FunctionAnalysis
from .use_define_analysis import SSAUseDefineAnalysis, StandardSSAVariable
from .dominator_tree import DominatorTreeAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable, MediumLevelILBasicBlock

import abc

import typing
from queue import Queue

import networkx

from .use_define_analysis import SSAUseDefineAnalysis

class CFGAnalysis(FunctionAnalysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def initialize(self, function: Function, fam: FunctionAnalysisManager):
        super().initialize(function, fam)
        self.__use_def: SSAUseDefineAnalysis = fam.get_function_analysis(SSAUseDefineAnalysis)

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)

        ssa_form: Function = function.mlil.ssa_form
        assert ssa_form
        
        self.__networkx_basic_block_graph: networkx.DiGraph = networkx.DiGraph()

        for bbl in ssa_form:
            for edge in bbl.outgoing_edges:
                assert edge.source is not None
                assert edge.target is not None
                self.__networkx_basic_block_graph.add_edge(edge.source, edge.target)
            for edge in bbl.incoming_edges:
                assert edge.source is not None
                assert edge.target is not None
                self.__networkx_basic_block_graph.add_edge(edge.source, edge.target)

    def has_path(self, src: MediumLevelILInstruction, dest: MediumLevelILInstruction):
        assert isinstance(src, MediumLevelILInstruction)
        assert isinstance(dest, MediumLevelILInstruction)
        src: MediumLevelILInstruction = self.__use_def.get_definition_instruction(src)
        dest: MediumLevelILInstruction = self.__use_def.get_definition_instruction(dest)


        src_bbl = src.il_basic_block
        dest_bbl = dest.il_basic_block
        if src_bbl != dest_bbl:
            return networkx.algorithms.shortest_paths.generic.has_path(self.__networkx_basic_block_graph, src_bbl, dest_bbl)

        if dest.expr_index > src.expr_index:
            return True
        
        try:
            networkx.find_cycle(self.__networkx_basic_block_graph, src_bbl)
        except networkx.NetworkXNoCycle:
            return False
        return True
        


