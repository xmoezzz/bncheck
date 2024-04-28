from .helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Function
from analysis.use_define_analysis import SSAUseDefineAnalysis
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation


class TestUseDefineAnalysis(unittest.TestCase):
    def setUp(self):
        self.module1 = load_test_module("./simple_example_1/main")
        self.mam1 = ModuleAnalysisManager(self.module1)

    def test_use_define_analysis(self):
        func: Function = self.module1.get_function_at(
            0x400530)  # main function
        instructions = list(func.mlil.ssa_form.instructions)
        use_def: SSAUseDefineAnalysis = self.mam1.get_function_analysis(
            SSAUseDefineAnalysis, func)
        assert isinstance(use_def, SSAUseDefineAnalysis)

        calling_instructions = []
        for inst in instructions:
            print(inst)
            if inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                calling_instructions.append(inst)
        assert len(calling_instructions) == 3

        ret = calling_instructions[0].output
        assert ret.operation == MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA
        ret_list = ret.dest

        assert len(ret_list) == 1
        ret = ret_list[0]

        users = set()
        users.add(ret)

        need_update = True
        while need_update:
            need_update = False
            more = set()
            for a in users:
                for v in use_def.get_users_of(a):
                    if v not in users:
                        need_update = True
                        more.add(v)
            users = users.union(more)

        assert calling_instructions[0] not in users
        assert calling_instructions[1] in users
        assert calling_instructions[2] in users
