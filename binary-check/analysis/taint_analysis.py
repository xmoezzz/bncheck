from .basic import ModuleAnalysisManager, Function, FunctionAnalysisManager, FunctionAnalysis
from .use_define_analysis import SSAUseDefineAnalysis, StandardSSAVariable
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable

import abc

import typing
from queue import Queue


class TaintAnalysisBase(FunctionAnalysis, abc.ABC):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__use_def_analysis: SSAUseDefineAnalysis = None

    def initialize(self, function: Function, fam: FunctionAnalysisManager):
        super().initialize(function, fam)

        self.__use_def_analysis = fam.get_function_analysis(
            SSAUseDefineAnalysis)

    def run_on_function(
            self,
            function: Function,
            fam: FunctionAnalysisManager):
        super().run_on_function(function, fam)

    @abc.abstractmethod
    def transfer(self, inst: MediumLevelILInstruction, transfer_taint) -> bool:
        pass

    def is_tainted_by(self, sink: StandardSSAVariable,
                      source: StandardSSAVariable) -> bool:
        if sink == source:
            return True
        
        tainted_set = set()
        in_queue = set()
        queue = Queue()

        def mark_tainted(sink):
            nonlocal tainted_set
            nonlocal in_queue
            nonlocal queue
            if sink not in tainted_set:
                tainted_set.add(sink)
                for user in self.__use_def_analysis.get_users_of(sink):
                    if user in in_queue:
                        break
                    else:
                        queue.put(user)
                        in_queue.add(user)

        def transfer_taint(sink, source):
            nonlocal tainted_set
            if sink in tainted_set:
                return
            if source in tainted_set:
                tainted_set.add(sink)
        
        self._transfer_taint = transfer_taint
        mark_tainted(source)

        while not queue.empty():
            var = queue.get()
            in_queue.remove(var)
            assert len(in_queue) == queue.qsize()

            if not isinstance(var, MediumLevelILInstruction):
                continue

            inst: MediumLevelILInstruction = var
            self._transfer(inst)
        return source in tainted_set

    def _transfer(self, inst: MediumLevelILInstruction):
        transfer_taint = self._transfer_taint
        if self.transfer(inst, transfer_taint):
            return

        if inst.operation in [MediumLevelILOperation.MLIL_SET_VAR_SSA]:
            transfer_taint(inst.dest, inst.src)
        elif inst.operation in [MediumLevelILOperation.MLIL_SET_VAR]:
            transfer_taint(inst.dest, inst.src)
        elif inst.operation in [MediumLevelILOperation.MLIL_VAR_SSA]:
            transfer_taint(inst, inst.src)
        elif inst.operation in [MediumLevelILOperation.MLIL_VAR]:
            transfer_taint(inst, inst.src)
        elif inst.operation == MediumLevelILOperation.MLIL_VAR_PHI:
            for src in inst.src:
                transfer_taint(inst.dest, src)
        elif inst.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            transfer_taint(inst.dest, inst.src)
        elif inst.operation == MediumLevelILOperation.MLIL_VAR_ALIASED:
            transfer_taint(inst, inst.src)
        elif inst.operation == MediumLevelILOperation.MLIL_MEM_PHI:
            for new_ssa_var in self.__use_def_analysis.get_all_ssa_var_in_memory_version(
                    inst.dest_memory):
                old_ssa_vars = []
                for old_version in inst.src_memory:
                    old_ssa_var = self.__use_def_analysis.get_ssa_var_of_memory_version(
                        old_version, new_ssa_var)
                    transfer_taint(new_ssa_var, old_ssa_var)

        elif inst.operation in [MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR]:
            pass

        elif inst.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
            transfer_taint(inst, inst.src)

        elif inst.operation in [
            MediumLevelILOperation.MLIL_ADD,
            MediumLevelILOperation.MLIL_AND,
            MediumLevelILOperation.MLIL_OR,
            MediumLevelILOperation.MLIL_XOR,
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
            transfer_taint(inst, inst.left)
            transfer_taint(inst, inst.right)

        elif inst.operation in [
            MediumLevelILOperation.MLIL_RLC,
            MediumLevelILOperation.MLIL_RRC,
            MediumLevelILOperation.MLIL_ADC,
            MediumLevelILOperation.MLIL_SBB,
        ]:
            transfer_taint(inst, inst.left)
            transfer_taint(inst, inst.right)

        elif inst.operation in [
            MediumLevelILOperation.MLIL_NEG,
            MediumLevelILOperation.MLIL_NOT,
            MediumLevelILOperation.MLIL_SX,
            MediumLevelILOperation.MLIL_ZX,
            MediumLevelILOperation.MLIL_LOW_PART,
        ]:
            transfer_taint(inst, inst.src)
