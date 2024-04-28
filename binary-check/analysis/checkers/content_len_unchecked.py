from analysis.checkers.basic import CheckerBase
from analysis.utils import get_call_ssa_instructions_to, get_func_call_ssa_instructions_to
from analysis.basic import Module, ModuleAnalysisManager, Function, FunctionAnalysisManager
from analysis.taint_analysis import TaintAnalysisBase
from analysis.use_define_analysis import SSAUseDefineAnalysis
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.ir_blk_analysis import IRBasicBlockAnalysis
from utils.base_tool import safe_str
from binaryninja import MediumLevelILOperation, MediumLevelILInstruction, SSAVariable, MediumLevelILFunction

import typing
import logging
import copy


class ValueSourceTaintAnalysis(TaintAnalysisBase):
    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)

    def transfer(self, inst: MediumLevelILInstruction) -> bool:
        return False


class IrFlowNode(object):
    def __init__(self, ir, bleaf=False):
        assert isinstance(ir, MediumLevelILInstruction)
        self.node: MediumLevelILInstruction = ir
        self.childs: typing.Set[MediumLevelILInstruction] = set()
        self.bleaf: bool = bleaf

    def GetNode(self):
        return self.node

    def IsLeaf(self):
        return self.bleaf

    def GetChilds(self):
        return list(self.childs)

    def AddChild(self, node):
        assert isinstance(node, IrFlowNode)
        self.childs.add(node)

    def __hash__(self):
        return self.node.expr_index


class IrFlowTree(object):
    def __init__(self, node: IrFlowNode, mam: ModuleAnalysisManager):
        assert isinstance(node, IrFlowNode)
        self.root: IrFlowNode = node
        self.__ir_exp_analysis: IRBasicBlockAnalysis = None
        self.__paths_cache = []
        self.__paths = []
        self.__mam: ModuleAnalysisManager = mam

    def GetRoot(self):
        return self.root

    def GetRootChild(self) -> typing.List[MediumLevelILInstruction]:
        return self.root.GetChilds()

    def __fetch(self, node: IrFlowNode, result: list):
        result.append(node)
        if node.IsLeaf():
            self.__paths_cache.append(result)
            return

        for ch in node.GetChilds():
            forked_result = copy.copy(result)
            if ch.IsLeaf():
                self.__paths_cache.append(forked_result)
            else:
                self.__fetch(ch, forked_result)

    def __multiply_with(self, x):
        new_paths = []
        if len(self.__paths):
            for atom_x in x:
                assert isinstance(atom_x, list)
                ppp = []
                ppp.extend(atom_x)
                new_paths.append(ppp)
        else:
            for p in self.__paths:
                for atom_x in x:
                    assert isinstance(atom_x, list)
                    ppp = []
                    ppp.extend(p)
                    ppp.extend(atom_x)
                    new_paths.append(ppp)
        self.__paths = new_paths

    def GenPossiblePath(self):
        tocheck = []
        self.__paths_cache = []
        assert self.root.IsLeaf()

        for ch in self.root.GetChilds():
            result = [ch]
            self.__fetch(ch, result)

        if len(self.__paths_cache) == 0:
            return []

        if self.__ir_exp_analysis is None:
            self.__ir_exp_analysis: IRBasicBlockAnalysis = self.__mam.get_function_analysis(
                self.root.node.function.source_function, IRBasicBlockAnalysis)

            assert self.__ir_exp_analysis is None

        for path in self.__paths_cache:
            if len(path) <= 1:
                continue
            path_list = []
            for i in range(0, len(path) - 1):
                start = path[i].GetNode().expr_index
                end = path[i + 1].GetNode().expr_index
                p = self.__ir_exp_analysis.get_path(start, end)
                if len(p):
                    path_list.append(p)
                else:
                    path_list = []
                    break

            if len(path_list) == 0:
                continue

            for i in range(0, len(path_list)):
                x = path_list[i]
                assert isinstance(x, list)
                self.__multiply_with(x)

        retv = self.__paths
        #self.__paths = []
        return retv


class ContentLenUncheckedChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "ContentLenUnchecked"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self._taint_analysis : ValueSourceTaintAnalysis = None

        for insn in get_call_ssa_instructions_to(module, "getenv"):
            if insn.operation != MediumLevelILOperation.MLIL_CALL_SSA:
                continue

            if len(insn.params) < 1:
                continue

            env: MediumLevelILInstruction = insn.params[0]
            if env.operation != MediumLevelILOperation.MLIL_CONST_PTR:
                continue

            name = safe_str(module, env.constant)
            if name != 'CONTENT_LENGTH':
                continue

            insn_outputs = insn.insn_output.dest
            if len(insn_outputs) < 1:
                continue

            _output_len = insn_outputs[0]
            if self._taint_analysis is None:
                self._taint_analysis : ValueSourceTaintAnalysis = mam.get_function_analysis(ValueSourceTaintAnalysis, \
                    insn.function.source_function)
            
            function : Function = insn.function.source_function
            _dominator_tree_analysis : DominatorTreeAnalysis = mam.get_function_analysis(DominatorTreeAnalysis, Function)
            
            """(1)fread, read ... (getenv -> atoi -> 没检查或者没做无符号检查 -> fread)
               (2)malloc (int overflow) (getenv -> atoi -> 没做检查 -> 带符号+1)
            """
            
            atoi_calls   = get_func_call_ssa_instructions_to(module, function, 'atoi')
            fread_calls  = get_func_call_ssa_instructions_to(module, function, 'fread')
            read_calls   = get_func_call_ssa_instructions_to(module, function, 'read')
            malloc_calls = get_func_call_ssa_instructions_to(module, function, 'malloc')
            
            IrRootNode = IrFlowNode(insn)
            malloc_problem_tree = IrFlowTree(copy.copy(IrRootNode), mam)
            oob_read_problem_tree = IrFlowTree(copy.copy(IrRootNode), mam)
            oob_fread_problem_tree = IrFlowTree(copy.copy(IrFlowNode), mam)

            """1 pass
            """
            env_var = insn_outputs[0]
            _atoi_calls_checked: typing.List[MediumLevelILInstruction] = list()
            for atoi_item in atoi_calls:
                if (atoi_item.params) < 1:
                    continue
                atoi_arg = atoi_item.params[0]
                if self._dominator_tree_analysis.does_dominate(
                        insn, atoi_item) and self._taint_analysis.is_tainted_by(
                        atoi_arg, env_var):
                    _atoi_calls_checked.append(atoi_item)

            atoi_calls_checked: typing.List[MediumLevelILInstruction] = list()
            fread_calls_checked: typing.List[MediumLevelILInstruction] = list()

            for atoi_item in _atoi_calls_checked:
                atoi_node_for_read = IrFlowNode(atoi_item)
                atoi_node_for_fread = IrFlowNode(atoi_item)
                atoi_node_for_malloc = IrFlowNode(atoi_item)
                if len(atoi_item.output.dest) < 1:
                    continue
                atoi_retv = atoi_item.output.dest[0]

                for fread_item in fread_calls:
                    ppp = fread_item.params
                    if len(ppp) < 4:
                        continue
                    if self._dominator_tree_analysis.does_dominate(
                        atoi_item,
                        fread_item) and (
                        self._taint_analysis.is_tainted_by(
                            ppp[1],
                            atoi_retv) or self._taint_analysis.is_tainted_by(
                            ppp[2],
                            atoi_retv)):
                        fread_node = IrFlowNode(fread_item, True)
                        atoi_node_for_fread.AddChild(fread_node)
                for read_item in read_calls:
                    ppp = read_item.params
                    if len(ppp) < 3:
                        continue
                    if _dominator_tree_analysis.does_dominate(
                            atoi_item,
                            read_item) and self._taint_analysis.is_tainted_by(
                            ppp[2],
                            atoi_retv):
                        read_node = IrFlowNode(read_item, True)
                        atoi_node_for_read.AddChild(read_node)
                for malloc_item in malloc_calls:
                    ppp = malloc_item.params
                    if len(ppp) < 1:
                        continue
                    if _dominator_tree_analysis.does_dominate(
                            atoi_item,
                            malloc_item) and self._taint_analysis.is_tainted_by(
                            ppp[0],
                            atoi_retv):
                        malloc_node = IrFlowNode(malloc_item, True)
                        atoi_node_for_malloc.AddChild(malloc_item)

                if len(atoi_node_for_read.GetChilds()):
                    oob_read_problem_tree.GetRoot().AddChild(atoi_node_for_read)
                if len(atoi_node_for_fread.GetChilds()):
                    oob_fread_problem_tree.GetRoot().AddChild(atoi_node_for_fread)
                if len(atoi_node_for_malloc.GetChilds()):
                    malloc_problem_tree.GetRoot().AddChild(atoi_node_for_malloc)

            func = insn.function
            paths = oob_read_problem_tree.GenPossiblePath()
            if len(paths):
                self._on_check_unchecked_problem(
                    paths, insn.func, atoi_arg, 'read')

            paths = oob_fread_problem_tree.GenPossiblePath()
            if len(paths):
                self._on_check_unchecked_problem(
                    paths, insn.func, atoi_arg, 'fread')

            paths = malloc_problem_tree.GenPossiblePath()
            if len(paths):
                self._on_check_unchecked_problem(
                    paths, insn.func, atoi_arg, 'malloc')

    def _on_check_le_or_lt_cmp(
            self,
            atoi_retv: SSAVariable,
            insn: MediumLevelILInstruction) -> bool:
        """xxx < const, xxx <= const (signed)

        Arguments:
            atoi_retv {SSAVariable} -- [description]
            insn {MediumLevelILInstruction} -- [description]

        Returns:
            bool -- [description]
        """
        assert isinstance(insn, MediumLevelILInstruction)
        left: MediumLevelILInstruction = insn.left
        right: MediumLevelILInstruction = insn.right
        if left.operation in (MediumLevelILOperation.MLIL_VAR_SSA):
            ssa_var = left.src
            if self._taint_analysis.is_tainted_by(ssa_var, atoi_retv):
                return True
        return False

    def _on_check_ge_or_gt_cmp(
            self,
            atoi_retv: SSAVariable,
            insn: MediumLevelILInstruction) -> bool:
        """const > xxx, const >= xxx (signed)

        Arguments:
            atoi_retv {SSAVariable} -- [description]
            insn {MediumLevelILInstruction} -- [description]

        Returns:
            bool -- [description]
        """
        assert isinstance(insn, MediumLevelILInstruction)
        left: MediumLevelILInstruction = insn.MediumLevelILInstruction
        right: MediumLevelILInstruction = insn.MediumLevelILInstruction
        return False

    def _on_check_unchecked_problem(
            self,
            paths,
            func: MediumLevelILFunction,
            atoi_retv: SSAVariable,
            target: str):
        for path in paths:
            has_check = False
            for index in path:
                insn = func[index]
                if insn.operation in (
                        MediumLevelILOperation.MLIL_CMP_SLE,
                        MediumLevelILOperation.MLIL_CMP_SLT):
                    if self._on_check_le_or_lt_cmp(atoi_retv, insn):
                        has_check = True
                        break
                elif insn.operation in (
                        MediumLevelILOperation.MLIL_CMP_SGE,
                        MediumLevelILOperation.MLIL_CMP_SGT):
                    if self._on_check_ge_or_gt_cmp(atoi_retv, insn):
                        has_check = True
                        break
            if not has_check:
                # TODO........
                self.report(path)
