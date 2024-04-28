from analysis.checkers.basic import CheckerBase
from analysis.utils import get_call_ssa_instructions_to, get_func_call_ssa_instructions_to
from analysis.basic import Module, ModuleAnalysisManager, Function, FunctionAnalysisManager
from analysis.taint_analysis import TaintAnalysisBase
from analysis.call_graph_analysis import CallGraphAnalysis, CrossReferenceItem
from analysis.dominator_tree import DominatorTreeAnalysis
from function_filters.targets import DestTarget
from function_filters.sources import SourceTarget
from function_filters.transfers import TaintSource
from function_filters.basic import FunctionType, FunctionParameterType, FunctionPrototype, \
    FunctionReturnType
from binaryninja import MediumLevelILOperation, MediumLevelILInstruction, SSAVariable, MediumLevelILFunction, \
    RegisterValueType
from utils.base_tool import get_callee_name, calc_format_string, safe_str

import typing
import logging
import copy
import enum
from analysis.use_define_analysis import StandardSSAVariable


logger = logging.getLogger(__name__)

class FunctionWrapper(object):
    def __init__(self, sink_arr, sinks, source_arr, sources):
        self.__sink_arr : typing.List[SSAVariable] = sink_arr
        self.__sinks    : typing.List[SSAVariable] = sinks
        self.__source_arr : typing.List[SSAVariable] = source_arr
        self.__sources  : typing.List[SSAVariable] = sources
    
    @property
    def sink_array(self) -> typing.List[SSAVariable]:
        return self.__sink_arr
    
    @sink_array.setter
    def sink_array(self, values):
        self.__sink_arr = values
    
    @property
    def sinks(self) -> typing.List[SSAVariable]:
        return self.__sinks
    
    @sinks.setter
    def sinks(self, values):
        self.__sinks = values
    
    @property
    def source_array(self) -> typing.List[SSAVariable]:
        return self.__source_arr
    
    @source_array.setter
    def source_array(self, values):
        self.__source_arr = values
    
    @property
    def sources(self) -> typing.List[SSAVariable]:
        return self.__sources
    
    @sources.setter
    def sources(self, values):
        self.__sources = values


class TransferMode(enum.IntEnum):
    """普通函数:所有的参数都应该是被调用位置的sink
    """
    NORMAL_FUNC = 0,
    """入口函数:所有带OUT属性的参数和我们需要的返回值都是source
    """
    SOURCE_FUNC = 1,
    """终止函数:所有带IN属性的都是sink
    """
    SYSTEM_FUNC = 2,
    """污染传递函数:所有带IN属性的参数是source，所有带OUT属性和我们需要的
       返回值都是sink
    """
    TRANS_FUNC  = 3
    

def switch_sink_source(w : FunctionWrapper, mode : TransferMode)->FunctionWrapper:
    if mode == TransferMode.SYSTEM_FUNC:
        sink_arr = w.sink_array
        sinks    = w.sinks
        w.sink_array = w.source_array
        w.sinks      = w.sources
        w.source_array = sink_arr
        w.sources      = sinks
    
    return w

def transfer_function(
    pp : FunctionPrototype, 
    module : Module, 
    call_insn : MediumLevelILInstruction, 
    mode : TransferMode = TransferMode.NORMAL_FUNC) -> typing.List[FunctionWrapper]:

    assert isinstance(call_insn, MediumLevelILInstruction)

    retv = []
    if pp.func_type == FunctionType.FUNC_NORMAL:
        def process_with_normal()->FunctionWrapper:
            sink_arr   : typing.List[SSAVariable] = []
            sinks      : typing.List[SSAVariable] = []
            source_arr : typing.List[SSAVariable] = []
            sources    : typing.List[SSAVariable] = []

            if pp.return_type == FunctionReturnType.R_OUT and len(call_insn.output.dest) > 0:
                sinks.append(call_insn.output.dest[0])
            index = 0
            for tt in pp.parameter_types:
                if index >= len(pp.parameter_types):
                    break

                param_insn : MediumLevelILInstruction = call_insn.params[index]
                if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                    if tt == FunctionParameterType.P_OUT:
                        sinks.append(param_insn.src)
                    elif tt == FunctionParameterType.P_IN:
                        sources.append(param_insn.src)
                    elif tt == FunctionParameterType.P_INARR:
                        source_arr.append(param_insn.src)
                    elif tt == FunctionParameterType.P_OUTARR:
                        sink_arr.append(param_insn.src)
                index += 1
            w = FunctionWrapper(sink_arr, sinks, source_arr, sources)
            return w
        
        ww = process_with_normal()
        retv.append(ww)

    elif pp.func_type == FunctionType.FUNC_PURE_VARARG:
        def process_with_vararg()->FunctionWrapper:
            sink_arr   : typing.List[SSAVariable] = []
            sinks      : typing.List[SSAVariable] = []
            source_arr : typing.List[SSAVariable] = []
            sources    : typing.List[SSAVariable] = []

            if pp.return_type == FunctionReturnType.R_OUT and len(call_insn.output.dest) > 0:
                sinks.append(call_insn.output.dest[0])
            index = 0
            for tt in pp.parameter_types:
                if index >= len(pp.parameter_types):
                    break

                param_insn : MediumLevelILInstruction = call_insn.params[index]
                if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                    if tt == FunctionParameterType.P_OUT:
                        sinks.append(param_insn.src)
                    elif tt == FunctionParameterType.P_IN:
                        sources.append(param_insn.src)
                    elif tt == FunctionParameterType.P_INARR:
                        source_arr.append(param_insn.src)
                    elif tt == FunctionParameterType.P_OUTARR:
                        sink_arr.append(param_insn.src)
                index += 1

            if index < len(call_insn.params):
                index = pp.var_index
                while index < len(call_insn.params):
                    param_insn : MediumLevelILInstruction = call_insn.params[index]
                    if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                        sinks.append(param_insn.src)
                    index += 1
            w = FunctionWrapper(sink_arr, sinks, source_arr, sources)
            return w
        
        ww = process_with_vararg()
        retv.append(ww)
            
    elif pp.func_type == FunctionType.FUNC_STR_VARARG:
        def process_with_fstr(fstr_const : int)->FunctionWrapper:
            assert isinstance(fstr_const, int)

            sink_arr   : typing.List[SSAVariable] = []
            sinks      : typing.List[SSAVariable] = []
            source_arr : typing.List[SSAVariable] = []
            sources    : typing.List[SSAVariable] = []
            fstr_val, _ = safe_str(module, fstr_const)

            var_count = calc_format_string(fstr_val)
            if pp.return_type == FunctionReturnType.R_OUT and len(call_insn.output.dest) > 0:
                sinks.append(call_insn.output.dest[0])
            index = 0
            try:
                for tt in pp.parameter_types:
                    if index >= len(pp.parameter_types):
                        break

                    param_insn : MediumLevelILInstruction = call_insn.params[index]
                    if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                        if tt == FunctionParameterType.P_OUT:
                            sinks.append(param_insn.src)
                        elif tt == FunctionParameterType.P_IN:
                            sources.append(param_insn.src)
                        elif tt == FunctionParameterType.P_INARR:
                            source_arr.append(param_insn.src)
                        elif tt == FunctionParameterType.P_OUTARR:
                            sink_arr.append(param_insn.src)
                    index += 1
            
                if index < len(call_insn.params):
                    index = pp.var_index
                    while index <= pp.var_index + var_count:
                        param_insn : MediumLevelILInstruction = call_insn.params[index]
                        if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                            sinks.append(param_insn.src)
                        index += 1
            
            except IndexError as e:
                ## 因为我们只能修复这种参数问题
                logger.warning("You need to apply prologue before using any checker!!!")
                raise IndexError from e

            w = FunctionWrapper(sink_arr, sinks, source_arr, sources)
            return w
        
        fstr : MediumLevelILInstruction = call_insn.params[pp.fstr_index]
        if fstr.operation not in (
            MediumLevelILOperation.MLIL_CONST,
            MediumLevelILOperation.MLIL_CONST_PTR
            ):
            ### assert 
            if fstr.possible_values.type != RegisterValueType.InSetOfValues:
                """就不要分析下去了...
                """
                return []

            """In set
            """
            retv = []
            for v in fstr.possible_values.values:
                ww = process_with_fstr(v)
                retv.append(ww)
        else:
            ww = process_with_fstr(fstr.constant)
            retv.append(ww)
    
    final_retv = []
    for ret in retv:
        final_retv.append(switch_sink_source(ret, mode))
    return final_retv
    

class CmdInjectTaintAnalysis(TaintAnalysisBase):
    def run_on_function(self, function:Function, fam: FunctionAnalysisManager):
        self.__fam : FunctionAnalysisManager = fam
        self.__func : Function = function
        self.__module : Module = fam.get_module()
        super().run_on_function(function, fam)
        
    
    def transfer(self, inst: MediumLevelILInstruction, transfer_taint) -> bool:
        if inst.operation in (
            MediumLevelILOperation.MLIL_TAILCALL_SSA,
            MediumLevelILOperation.MLIL_CALL_SSA
            ):
            name = get_callee_name(self.__module, inst)
            if name is None:
                return False
            if name not in TaintSource:
                return False
            
            item = TaintSource[name]
            pp = FunctionPrototype(name, item)
            pp.initialize(item)
            """我们需要一个路径敏感的分析...
            """
            ww = transfer_function(pp, self.__module, inst, TransferMode.TRANS_FUNC)
            if len(ww) > 1:
                return False
            
            w = ww[0]
            for sink in w.sinks:
                for source in w.sources:
                    transfer_taint(sink, source)
            return True
        return False
            
class CmdInjectInprocedureReportItem(object):
    def __init__(self, func : Function, sink : SSAVariable, sink_insn : MediumLevelILInstruction, source : SSAVariable, source_insn : MediumLevelILInstruction):
        self.func : Function = func
        self.sink : SSAVariable = sink
        self.sink_insn : MediumLevelILInstruction = sink_insn
        self.source : SSAVariable = source
        """source_insn可能是空的,代表这个source来自当前函数的参数列表
        """
        self.source_insn : MediumLevelILInstruction = source_insn
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        return "command inject : (in-procedure):\nfunction : %s\nsink : %s\nsink instruction : %s\nsource : %s\nsource instruction : %s\n\n" % (
            self.func,
            self.sink,
            self.sink_insn,
            self.source,
            self.source_insn
        )

class CmdInjectInterprocedureReportItem(object):
    def __init__(self, chain : typing.List[CmdInjectInprocedureReportItem]):
        self.chain : typing.List[CmdInjectInprocedureReportItem] = chain
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        retv = "command inject : (inter-procedure)\n"
        for item in self.chain:
            retv += "------------------------\n"
            retv += "function : %s\nsink : %s\nsink instruction : %s\nsource : %s\nsource instruction : %s\n" % (
                item.func,
                item.sink,
                item.sink_insn,
                item.source,
                item.source_insn
            )
            retv += "------------------------\n"
        
        retv += "\n\n"
        return retv

class CmdInjectInfo(object):
    def __init__(self, func : Function, insn : MediumLevelILInstruction):
        self.func : Function = func
        self.insn : MediumLevelILInstruction = insn
        self.call_chain : typing.List[CmdInjectInprocedureReportItem] = list()
        self.visited_function = set()
    
    def push(self, item : CmdInjectInprocedureReportItem)->bool:
        """我们是否已经来过这个函数了
        """
        assert isinstance(item, CmdInjectInprocedureReportItem)
        if item.func in self.visited_function:
            return False
        self.visited_function.add(item.func)
        self.call_chain.append(item)
        return True
    
    def convert_to_report(self):
        return CmdInjectInterprocedureReportItem(copy.copy(self.call_chain))
    
    def fork(self):
        item = CmdInjectInfo(self.func, self.insn)
        item.call_chain = copy.copy(self.call_chain)
        return item
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        return str(self.convert_to_report())
        

class CmdInjectChecker(CheckerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__max_call_depth = 20
        self.__call_depth = self.__max_call_depth
        if "call_depth" in kwargs:
            assert isinstance(kwargs["call_depth"], int)
            self.__call_depth = kwargs["call_depth"]
        if self.__call_depth > self.__max_call_depth:
            logging.warning("call_depth is too large")
            self.__call_depth = self.__max_call_depth
        if self.__call_depth < 0:
            logging.warning("call_depth is too small")
            self.__call_depth = self.__max_call_depth
    
    @staticmethod
    def get_checker_name()->str:
        return "CmdInject"
        
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__call_graph_analysis : CallGraphAnalysis = mam.get_module_analysis(CallGraphAnalysis)
        self.__mam : ModuleAnalysisManager = mam
        self.__module : Module = module
        
        for name, target_info in DestTarget.items():
            calls : typing.List[MediumLevelILInstruction] = get_call_ssa_instructions_to(module, name)
            if len(calls) == 0:
                continue
            for call_insn in calls:
                if call_insn.operation not in (
                    MediumLevelILOperation.MLIL_CALL_SSA,
                    MediumLevelILOperation.MLIL_TAILCALL_SSA
                    ):
                    continue
                name : str = get_callee_name(module, call_insn)
                if name not in DestTarget:
                    continue

                item : dict = DestTarget[name]
                pp = FunctionPrototype(name, item['type'])
                pp.initialize(item)
                wrapper_list = transfer_function(pp, self.__module, call_insn, TransferMode.SYSTEM_FUNC)
                if len(wrapper_list) == 0:
                    continue
                func : Function = call_insn.function.source_function
                for function_wrapper in wrapper_list:
                    info = CmdInjectInfo(func, call_insn)
                    self.__on_check_taint_inter_procedure(info, function_wrapper, call_insn, 0)
    
    def __on_check_taint_in_procedure_internal(self, info : CmdInjectInfo, w : FunctionWrapper, insn : MediumLevelILInstruction)->typing.List[CmdInjectInprocedureReportItem]:
        
        retv = []
        func : Function = insn.function.source_function
        dominator_tree_analysis : DominatorTreeAnalysis = self.__mam.get_function_analysis(DominatorTreeAnalysis, func)
        cmdi_taint_analysis : CmdInjectTaintAnalysis = self.__mam.get_function_analysis(CmdInjectTaintAnalysis, func)
        for blk in func.mlil.ssa_form:
            for inst in blk:
                if inst.operation not in (
                    MediumLevelILOperation.MLIL_CALL_SSA,
                    MediumLevelILOperation.MLIL_TAILCALL_SSA
                    ):
                    continue
                name = get_callee_name(self.__module, inst)
                if name is None:
                    continue
                if name not in SourceTarget:
                    continue
                source_target = SourceTarget[name]
                if dominator_tree_analysis.does_dominate(inst, insn) == False:
                    continue

                pp : FunctionPrototype = FunctionPrototype(name, source_target["type"])
                pp.initialize(source_target)
                wrapper_list = transfer_function(pp, self.__module, inst, TransferMode.SOURCE_FUNC)
                for func_wrapper in wrapper_list:
                    """TODO
                       这里的描述不太对,source function的output应该是source才对
                    """
                    for sink in func_wrapper.sinks:
                        for source in w.sinks:
                            if cmdi_taint_analysis.is_tainted_by(sink, source):
                                report = CmdInjectInprocedureReportItem(
                                    func,
                                    sink,
                                    inst,
                                    source,
                                    insn
                                    )
                                retv.append(report)
        return retv
    
    def __collect_function_parameters(self, func : Function) -> typing.List[SSAVariable]:
        retv = []
        for v in func.parameter_vars.vars:
            ssa = SSAVariable(v, 0)
            retv.append(ssa)
        return retv

    def __on_check_taint_inter_procedure(self, info : CmdInjectInfo, w : FunctionWrapper, insn : MediumLevelILInstruction, depth : int):
        """调用间
           我们不需要做一个call chain
        """
        func : Function = insn.function.source_function
        parameters = self.__collect_function_parameters(func)
        cmdi_taint_analysis : CmdInjectTaintAnalysis = self.__mam.get_function_analysis(CmdInjectTaintAnalysis, func)
        retv = self.__on_check_taint_in_procedure_internal(info, w, insn)
        if len(retv):
            for ret in retv:
                self.report(ret)
        
        if depth >= self.__call_depth:
            return 
        
        args_hint : typing.Set[int] = set()
        for idx, source in enumerate(parameters):
            for sink in w.sinks:
                if not cmdi_taint_analysis.is_tainted_by(sink, source):
                    continue
                args_hint.add(idx)
        
        if len(args_hint):
            child = info.fork()
            report = CmdInjectInprocedureReportItem(
                func,
                sink,
                insn,
                source,
                None
            )
            state = child.push(report)
            if not state:
                return
                
            """我们可能缺乏正确的type info, 我们应该信赖bn的结果么
            """
            cross_refs = self.__call_graph_analysis.get_cross_reference_by(func)
            for cross_ref in cross_refs:
                #FIX : 我们需要重新封装参数
                next_func = cross_ref.function
                next_insn = cross_ref.insn
                new_args : typing.List[SSAVariable] = list()
                for new_idx, param_insn in enumerate(next_insn.params):
                    if param_insn.operation == MediumLevelILOperation.MLIL_VAR_SSA and new_idx in args_hint:
                        new_args.append(param_insn.src)
                
                www = FunctionWrapper([], new_args, [], [])
                """是否应该路径敏感?
                """
                self.__on_check_taint_inter_procedure(
                    child,
                    www,
                    next_insn,
                    depth + 1
                    )
                    
