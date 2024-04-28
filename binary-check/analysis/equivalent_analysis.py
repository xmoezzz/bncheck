"""
目前的算法就是简单的GVN
#https://cseweb.ucsd.edu/classes/sp02/cse231/lec10seq.pdf

A is congruent to B if:
    1. A is exact B, or
    2. A and B are constant nodes, with the same constant value, or
    3. A and B are operator(expression), which have same operator, and their like operands are congruent
A and B are equivalent at P if:
    1. A and B are congruent and
    2. Both A and B dominate P
"""
from .basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, FunctionAnalysis
from .use_define_analysis import SSAUseDefineAnalysis, StandardSSAVariable
from .dominator_tree import DominatorTreeAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable

import abc

import typing
from queue import Queue


class CongruentIDUnionFindSet(object):
    def __init__(self):
        self._parent = {}
        self._all = {}
        return

    def get_parent(self, target: int) -> int:
        assert isinstance(target, int)
        if target not in self._parent:
            self._parent[target] = target
            self._all[target] = set([target])
        return self._parent[target]

    def get_root(self, target: int) -> int:
        if self.get_parent(target) == target:
            return target
        root = self.get_root(self.get_parent(target))
        self._parent[target] = root
        return root

    def union(self, left: int, right: int):
        root1 = self.get_root(left)
        root2 = self.get_root(right)
        self._parent[root1] = root2
        self._all[root2].update(self._all[root1])
        self._all.pop(root1)

    def get_all(self, target: int):
        root = self.get_root(target)
        return self._all[root]

    def same(self, left, right):
        return self.get_root(left) == self.get_root(right)


class EquivalentAnalysis(FunctionAnalysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def initialize(self, function: Function, fam: FunctionAnalysisManager):
        super().initialize(function, fam)
        self._used_max_id = 0
        self._id_to_expr = {}
        self.__ssa_var_to_id = {}
        self.__id_to_ssa_var = {}
        self.__union_set: CongruentIDUnionFindSet = CongruentIDUnionFindSet()
        self.__use_def_analysis: SSAUseDefineAnalysis = fam.get_function_analysis(
            SSAUseDefineAnalysis)
        self.__domtree_analysis: DominatorTreeAnalysis = fam.get_function_analysis(
            DominatorTreeAnalysis)
        self.__in_queue: typing.Set[StandardSSAVariable] = set()
        self.__queue: typing.Deque[StandardSSAVariable] = Queue()
        self.__fam = fam

    def get_id(self, var):
        if var not in self.__ssa_var_to_id:
            self._used_max_id += 1
            self.__ssa_var_to_id[var] = self._used_max_id
            self.__id_to_ssa_var[self._used_max_id] = var
        return self.__ssa_var_to_id[var]

    def get_ssa_var_by_id(self, _id):
        assert _id in self.__id_to_ssa_var

    def are_congruent(
            self,
            left: StandardSSAVariable,
            right: StandardSSAVariable):
        left_id = self.get_id(left)
        right_id = self.get_id(right)
        return self.__union_set.same(left_id, right_id)

    def are_equivalent(
            self,
            left: StandardSSAVariable,
            right: StandardSSAVariable,
            inst: typing.Optional[MediumLevelILInstruction] = None) -> bool:
        if not self.are_congruent(left, right):
            return False
        left_instruction = self.__use_def_analysis.get_definition_instruction(
            left)
        right_instruction = self.__use_def_analysis.get_definition_instruction(
            right)
        if left_instruction is None or right_instruction is None:
            #assert left == right
            return True  # in this case, `left` and `right` should be same?
        if inst is None:
            return True

        location_instruction = self.__use_def_analysis.get_definition_instruction(
            inst)
        assert location_instruction is not None
        """ # this code is totally wrong
        if isinstance(left, MediumLevelILInstruction):
            left = left.vars_read
        else:
            left = [left]
        if isinstance(right, MediumLevelILInstruction):
            right = right.vars_read
        else:
            right = [right]

        for v in left + right:
            define_instruction = self.__use_def_analysis.get_definition_instruction(v)
            if define_instruction is None:
                continue # parameter?
            if not self.__domtree_analysis.does_dominate(define_instruction, location_instruction, True):
                return False
        return True
        """
        return self.__domtree_analysis.does_dominate(
            left_instruction,
            location_instruction) and self.__domtree_analysis.does_dominate(
            right_instruction,
            location_instruction)

    def pre_hook_on_inst(self, inst: MediumLevelILInstruction, helper_union) -> bool:
        return False

    def helper_union(self,
            left: StandardSSAVariable,
            right: StandardSSAVariable):
        if self.are_congruent(left, right):
            return
        self.__union_set.union(self.get_id(left), self.get_id(right))
        #for lr in [left, right]:

        #找到新等价类中的所有元素
        for lr in map(lambda var_id: self.get_ssa_var_by_id(var_id), self.__union_set.get_all(self.get_id(left))):
            if not self.are_congruent(lr, left):
                continue
            for user in self.__use_def_analysis.get_users_of(lr):
                if user not in self.__in_queue:
                    self.__in_queue.add(user)
                    self.__queue.put(user)

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)


        all_inst = list(self.__use_def_analysis.get_all_variables())
        all_inst = list(
            filter(
                lambda x: isinstance(
                    x,
                    MediumLevelILInstruction),
                all_inst))
        self.__all_inst = all_inst
        for inst in all_inst:
            self.__in_queue.add(inst)
            self.__queue.put(inst)

        while not self.__queue.empty():
            var = self.__queue.get()
            self.__in_queue.remove(var)
            assert len(self.__in_queue) == self.__queue.qsize()

            if not isinstance(var, MediumLevelILInstruction):
                continue

            inst: MediumLevelILInstruction = var

            if self.pre_hook_on_inst(inst, self.helper_union):
                continue

            if inst.operation in [MediumLevelILOperation.MLIL_SET_VAR_SSA]:
                self.helper_union(inst.dest, inst.src)
                continue
            elif inst.operation in [MediumLevelILOperation.MLIL_SET_VAR]:
                self.helper_union(inst.dest, inst.src)
                continue
            elif inst.operation in [MediumLevelILOperation.MLIL_VAR_SSA]:
                self.helper_union(inst, inst.src)
                continue
            elif inst.operation in [MediumLevelILOperation.MLIL_VAR]:
                self.helper_union(inst, inst.src)
                continue
            elif inst.operation == MediumLevelILOperation.MLIL_VAR_PHI:
                for l, r in zip(inst.src[:-1], inst.src[1:]):
                    if not self.are_congruent(l, r):
                        break
                else:
                    # all source are congruent
                    for src in inst.src:
                        self.helper_union(inst.dest, src)
            elif inst.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                self.helper_union(inst.dest, inst.src)
                continue
            elif inst.operation == MediumLevelILOperation.MLIL_VAR_ALIASED:
                self.helper_union(inst, inst.src)
                continue
            elif inst.operation == MediumLevelILOperation.MLIL_MEM_PHI:
                continue

            elif inst.operation in [MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR]:
                for inst2 in all_inst:
                    if inst2 in [
                            MediumLevelILOperation.MLIL_CONST,
                            MediumLevelILOperation.MLIL_CONST_PTR] and inst2.constant == inst.constant and inst2.size == inst.size:
                        self.helper_union(inst, inst2)
                continue

            elif inst.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                for inst2 in all_inst:
                    if inst2.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                        if inst.src == inst2.src:
                            self.helper_union(inst, inst2)
                continue

            elif inst.operation == MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
                for inst2 in all_inst:
                    if inst2.operation == MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
                        if inst.src == inst2.src and inst.offset == inst2.offset:
                            self.helper_union(inst, inst2)
                continue

            elif inst.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
                for inst2 in all_inst:
                    if inst2.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
                        if self.are_congruent(
                                inst.src,
                                inst2.src) and inst.offset == inst2.offset and inst.size == inst2.size:
                            self.helper_union(inst, inst2)
                continue

            elif inst.operation in [
                MediumLevelILOperation.MLIL_ADD,
                MediumLevelILOperation.MLIL_AND,
                MediumLevelILOperation.MLIL_OR,
                MediumLevelILOperation.MLIL_XOR
            ]:
                for inst2 in all_inst:
                    if inst2.operation == inst.operation:
                        if (
                            self.are_congruent(
                                inst.left,
                                inst2.left) and self.are_congruent(
                                inst.right,
                                inst2.right)) or (
                            self.are_congruent(
                                inst.left,
                                inst2.right) and self.are_congruent(
                                inst.right,
                                inst2.left)):
                            self.helper_union(inst, inst2)

            elif inst.operation in [
                MediumLevelILOperation.MLIL_SUB,
                MediumLevelILOperation.MLIL_LSL,
                MediumLevelILOperation.MLIL_LSR,
                MediumLevelILOperation.MLIL_ASR,
                MediumLevelILOperation.MLIL_ROL,
                MediumLevelILOperation.MLIL_ROR,
                MediumLevelILOperation.MLIL_MUL,
                MediumLevelILOperation.MLIL_DIVU,
                MediumLevelILOperation.MLIL_DIVS,
                MediumLevelILOperation.MLIL_MODU,
                MediumLevelILOperation.MLIL_MODS,
                MediumLevelILOperation.MLIL_CMP_E,
                MediumLevelILOperation.MLIL_CMP_NE,
                MediumLevelILOperation.MLIL_CMP_SLT,
                MediumLevelILOperation.MLIL_CMP_ULT,
                MediumLevelILOperation.MLIL_CMP_SLE,

                MediumLevelILOperation.MLIL_MULU_DP,
                MediumLevelILOperation.MLIL_MULS_DP,
                MediumLevelILOperation.MLIL_DIVU_DP,
                MediumLevelILOperation.MLIL_DIVS_DP,
                MediumLevelILOperation.MLIL_MODS_DP,
                MediumLevelILOperation.MLIL_MODS_DP,
            ]:
                for inst2 in all_inst:
                    if inst2.operation == inst.operation:
                        if (self.are_congruent(inst.left, inst2.left)
                                and self.are_congruent(inst.right, inst2.right)):
                            self.helper_union(inst, inst2)

            elif inst.operation in [
                MediumLevelILOperation.MLIL_RLC,
                MediumLevelILOperation.MLIL_RRC,
                MediumLevelILOperation.MLIL_ADC,
                MediumLevelILOperation.MLIL_SBB,
            ]:
                for inst2 in all_inst:
                    if inst2.operation == inst.operation:
                        if self.are_congruent(
                            inst.left, inst2.left) and self.are_congruent(
                            inst.right, inst2.right and self.are_congruent(
                                inst.carry, inst2.carry)):
                            self.helper_union(inst, inst2)

            elif inst.operation in [
                MediumLevelILOperation.MLIL_NEG,
                MediumLevelILOperation.MLIL_NOT,
                MediumLevelILOperation.MLIL_SX,
                MediumLevelILOperation.MLIL_ZX,
                MediumLevelILOperation.MLIL_LOW_PART,
            ]:
                for inst2 in all_inst:
                    if inst2.operation == inst.operation:
                        if self.are_congruent(inst.src, inst2.src):
                            self.helper_union(inst, inst2)
