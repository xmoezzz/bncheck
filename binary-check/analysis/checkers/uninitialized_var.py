from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.use_define_analysis import SSAUseDefineAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.utils import get_call_ssa_instructions_to

from binaryninja import MediumLevelILOperation, MediumLevelILInstruction, \
    SSAVariable, MediumLevelILFunction, VariableSourceType

import typing
import logging

logger = logging.getLogger(__name__)


class UninitializedVarReport(object):
    def __init__(self, v : SSAVariable, owner : Function):
        self.__var : SSAVariable = v
        self.__owner : Function = owner
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        return "=====================\nuninitialized ssa variable : (%s)\nfunction : (%s)\n=====================\n\n" % (
            self.__var,
            self.__owner
        )
    
    @property
    def owner(self)->Function:
        return self.__owner
    
    @property
    def var(self)->SSAVariable:
        return self.__var

class UninitializedVarChecker(CheckerBase):
    @staticmethod
    def get_checker_name()->str:
        return "UninitializedVar"
    
    def __collect_alias(self, func : Function)->typing.Set[SSAVariable]:
        sets : typing.Set[SSAVariable] = set()
        for blk in func.mlil.ssa_form:
            for inst in blk:
                if inst.operation in (
                    MediumLevelILOperation.MLIL_SET_VAR_ALIASED,
                    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD
                    ):
                    sets.add(inst.prev)
        return sets
    
    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        for func in module.functions:
            use_define_analysis : SSAUseDefineAnalysis = mam.get_function_analysis(SSAUseDefineAnalysis, func)
            variables = use_define_analysis.get_all_variables()
            mlfunc : MediumLevelILFunction = func.mlil.ssa_form
            parameter_names = set()
            for var in func.parameter_vars.vars:
                parameter_names.add(var.name)
            
            for v in variables:
                if isinstance(v, SSAVariable):
                    d = mlfunc.get_ssa_var_definition(v)
                    if d is None and v.var.name not in parameter_names:
                        """ignore register type
                        """
                        if v.var.source_type != VariableSourceType.StackVariableSourceType:
                            continue
                        """一个stack上的变量没被用过，那么version一定为0
                        """
                        if v.version != 0:
                            continue
                        """__return_addr#0 过滤
                        """
                        if v.var.name.startswith('__'):
                            continue

                        sets = self.__collect_alias(func)
                        if v in sets:
                            continue
                        
                        rp = UninitializedVarReport(v, func)
                        self.report(rp)


