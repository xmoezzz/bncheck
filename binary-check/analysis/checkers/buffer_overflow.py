from .basic import CheckerBase
from ..basic import Function, Module, ModuleAnalysisManager, FunctionAnalysisManager, AnalysisManager
from ..dataflow_analysis import SSADataFlowState, SSADataFlowAnalysisOperationBase, SSADataFlowAnalysisBase, SSAInterprocedureDataFlowAnalysisBase
from ..value_set_analysis import SimpleValueSetAnalysis
from ..use_define_analysis import StandardSSAVariable
from binaryninja.types import Symbol
from binaryninja.mediumlevelil import MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from binaryninja.enums import VariableSourceType
import typing
from ..utils import get_call_ssa_instructions_to, get_call_ssa_dest_name

from ..use_define_analysis import SSAUseDefineAnalysis


class PointerSize(SSADataFlowState):
    def __init__(self, value=None, source=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.value = value
        self.source = source

    def __eq__(self, other):
        if not isinstance(other, PointerSize):
            return False
        retv = self.value == other.value  # NOTE, 注意这里实际上，我们，仅仅关心这个pointer的大小，而不是这个
        return retv

    def __str__(self):
        if self.value is None:
            return "<MAX>"
        else:
            return "<%d>" % self.value

    def __repr__(self):
        return self.__str__()


class PointerSizeAnalysisOperation(SSADataFlowAnalysisOperationBase):

    def initialize(self,
                   function_or_module: typing.Union[Function,
                                                    Module],
                   am: AnalysisManager):
        super().initialize(function_or_module, am)
        self.__am = am

    def meet(self, target_ssa_var: PointerSize, *
             args: typing.Sequence[PointerSize]) -> PointerSize:
        retv = None
        source = None
        for vv in args:
            if vv.value is None:
                return PointerSize()
            if retv is None:
                retv = vv.value
                source = vv.source
            else:
                if vv.value > retv:
                    retv = vv.value
                    source = vv.source
        return PointerSize(retv, source)

    def join(self, target_ssa_var: PointerSize, *
             args: typing.Sequence[PointerSize]) -> PointerSize:
        retv = None
        source = None
        for vv in args:
            if vv.value is None:
                continue
            if retv is None:
                retv = vv.value
                source = vv.source
            else:
                if vv.value < retv:
                    retv = vv.value
                    source = vv.source
        return PointerSize(retv, source)

    def get_default_state(self, var: StandardSSAVariable) -> SSADataFlowState:
        return PointerSize()

    def trans(self, inst: MediumLevelILInstruction) -> bool:
        function = inst.function.source_function
        value_set = self.__am.get_function_analysis(
            SimpleValueSetAnalysis, function)

        if inst.operation in [
                MediumLevelILOperation.MLIL_CALL_SSA,
                MediumLevelILOperation.MLIL_TAILCALL_SSA]:
            callee_name = get_call_ssa_dest_name(self.__am.get_module(), inst)
            if callee_name is None:
                return False
            if len(inst.output.dest) < 1:
                return False

            ret = inst.output.dest[0]

            if callee_name.strip("_") in [
                    "malloc", "kmalloc"] and len(
                    inst.params) >= 1:
                s = value_set.get_state_of(inst.params[0])
                if len(s) != 0:
                    self.update_var_state(ret, PointerSize(max(s), inst))
                else:
                    self.update_var_state(ret, PointerSize())
                return True
            if callee_name.strip("_") == "calloc" and len(inst.params) >= 2:
                s1 = value_set.get_state_of(inst.params[0])
                s2 = value_set.get_state_of(inst.params[1])
                if len(s1) != 0 and len(s2) != 0:
                    self.update_var_state(
                        ret, PointerSize(
                            max(s1) * max(s2), inst))
                else:
                    self.update_var_state(ret, PointerSize())
            if callee_name.strip("_") == "realloc" and len(inst.params) >= 2:
                s = value_set.get_state_of(inst.params[1])
                if len(s) != 0:
                    self.update_var_state(ret, PointerSize(max(s), inst))
                else:
                    self.update_var_state(ret, PointerSize())
                return True

        if inst.operation in [MediumLevelILOperation.MLIL_ADD]:
            value = None
            if self.get_state_of(
                    inst.left).value is not None and self.get_state_of(
                    inst.right).value is None:
                value = self.get_state_of(inst.left).value
                source = self.get_state_of(inst.left).source
                s = value_set.get_state_of(inst.right)
            if self.get_state_of(
                    inst.right).value is not None and self.get_state_of(
                    inst.left).value is None:
                value = self.get_state_of(inst.right).value
                source = self.get_state_of(inst.right).source
                s = value_set.get_state_of(inst.left)
            if value is not None:
                if len(s) == 0:
                    return True
                v = min(s)  # TODO: kill those negative values
                value -= v
                self.update_var_state(inst, PointerSize(value, source))
                return True
            return False
        if inst.operation in [
                MediumLevelILOperation.MLIL_ADDRESS_OF,
                MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD]:
            var = inst.src
            if inst.operation == MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
                offset = inst.offset
            else:
                offset = 0
            if var.source_type == VariableSourceType.StackVariableSourceType:
                # well, since most function push argument on stack, we make
                # sure we don't false positively report it
                size = - var.storage - offset + 0x100
                if size > 0:
                    self.update_var_state(inst, PointerSize(size, inst))
            return True

        # TODO: add ADDRESS_OF, so we can detect stackoverflow


class PointerSizeAnalysis(
        PointerSizeAnalysisOperation,
        SSADataFlowAnalysisBase):
    pass


class PointerSizeAnalysis(
        PointerSizeAnalysisOperation,
        SSAInterprocedureDataFlowAnalysisBase):
    def update_var_state(self, var, state):
        super().update_var_state(var, state)
    pass


class BufferOverflowChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "BufferOverflow"
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        functions = set()
        #ALLOCATORS = ["malloc", "realloc"]
        # for allocator in ALLOCATORS:
        #    for inst in get_call_ssa_instructions_to(module, allocator):
        #        functions.add(inst.function.source_function)
        functions = set(module.functions)

        function: Function
        for i, function in enumerate(functions):
            pointer_size: PointerSizeAnalysis = mam.get_module_analysis(
                PointerSizeAnalysis)
            use_def: SSAUseDefineAnalysis = mam.get_function_analysis(
                SSAUseDefineAnalysis, function)
            value_set_analysis: SimpleValueSetAnalysis = mam.get_function_analysis(
                SimpleValueSetAnalysis, function)

            def report_if_smaller(pointer, size, location_expr, size_add=0):
                if isinstance(size, int):
                    size = size
                else:
                    s = value_set_analysis.get_state_of(size)
                    if len(s) == 0:
                        return
                    size = min(s)
                size += size_add
                v = pointer_size.get_state_of(pointer)
                if v.value is not None and v.value < size and v.value >= - \
                        0x40000000:  # positive value
                    # with open("log", "a") as f:
                    #    f.write("%s\n" % [location_expr.function.source_function.name, location_expr, v.source])
                    self.report([location_expr, v.source])

            for var in use_def.get_all_variables():
                if not isinstance(var, MediumLevelILInstruction):
                    continue
                inst: MediumLevelILInstruction = var
                if inst.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                    report_if_smaller(inst.src, inst.size, inst)
                elif inst.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                    report_if_smaller(inst.dest, inst.size, inst)
                elif inst.operation in [MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA]:
                    check_dict = {
                        "memcpy": [(0, 2), (1, 2)],
                        "memcmp": [(0, 2), (1, 2)],
                        "memmove": [(0, 2), (1, 2)],
                        "snprintf": [(0, 1)],
                        "memmem": [(0, 1), (2, 3)],
                        "memset": [(0, 2)],
                    }
                    callee_name = get_call_ssa_dest_name(module, inst)
                    if callee_name is not None:
                        callee_name = callee_name.strip("_")
                    if callee_name in check_dict:
                        for pointer_i, size_i in check_dict[callee_name]:
                            if len(inst.params) <= max(pointer_i, size_i):
                                continue
                            pointer = inst.params[pointer_i]
                            size = inst.params[pointer_i]
                            report_if_smaller(pointer, size, inst)
                    elif callee_name == "strncat":
                        if len(inst.params) >= 3:
                            pointer = inst.params[0]
                            size = inst.params[2]
                            report_if_smaller(pointer, size, inst, 1)
                    else:
                        pass
                        # for param in inst.params: # too many FP
                        #    report_if_smaller(param, 0, inst)
