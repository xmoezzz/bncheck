import abc
import typing
from collections import defaultdict

from binaryninja import BinaryView as Module
from binaryninja import Function
from binaryninja import MediumLevelILInstruction

MediumLevelILInstruction.__hash__ = lambda self: hash(
    (self.function, self.expr_index))


class Analysis(abc.ABC):

    # @abc.abstractclassmethod
    # FIXME: to do , determine if we need this...?
    def get_analysis_usage(cls) -> typing.Sequence[typing.Type['Analysis']]:
        '''
        This function should return a sequence of needed analysis
        '''
        raise NotImplementedError()


class FunctionAnalysis(Analysis):

    def initialize(
            self,
            function: Function,
            analysis_manager: 'FunctionAnalysisManager'):
        pass

    @abc.abstractmethod
    def run_on_function(
            self,
            function: Function,
            analysis_manager: 'FunctionAnalysisManager'):
        pass


class ModuleAnalysis(Analysis):

    def initialize(
            self,
            module: Module,
            analysis_manager: 'ModuleAnalysisManager'):
        pass

    @abc.abstractmethod
    def run_on_module(
            self,
            module: Module,
            analysis_manager: 'ModuleAnalysisManager'):
        pass


class AnalysisManager(abc.ABC):
    @abc.abstractmethod
    def get_function_analysis(
            self,
            analysis_class: typing.Type[Analysis],
            function: typing.Optional[Function]) -> FunctionAnalysis:
        pass

    @abc.abstractmethod
    def get_module_analysis(
            self,
            analysis_class: typing.Type[Analysis],
            module: typing.Optional[Module]) -> ModuleAnalysis:
        pass


class ModuleAnalysisManager(object):
    def __init__(self, module: Module):
        assert module is not None
        assert isinstance(module, Module)

        self._module = module
        self._module_analysis = {}
        self._function_analysis = defaultdict(dict)
        self._cache_function_analysis_manager = dict()
        pass

    def get_module_analysis(
            self,
            analysis_class: typing.Type[Analysis],
            module: typing.Optional[Module] = None) -> ModuleAnalysis:

        assert isinstance(module, Module) or (module is None)

        if module is None:
            module = self._module

        assert (self._module == module)

        assert issubclass(analysis_class, ModuleAnalysis)

        module_analysis = self._module_analysis.get(analysis_class)

        if module_analysis is None:
            module_analysis = analysis_class()
            module_analysis.initialize(module, self)
            module_analysis.run_on_module(module, self)
            self._module_analysis[analysis_class] = module_analysis

        return module_analysis

    def get_function_analysis(self,
                              analysis_class: typing.Type[Analysis],
                              function: Function) -> FunctionAnalysis:

        assert isinstance(function, Function)
        assert issubclass(analysis_class, FunctionAnalysis)

        #assert function.get_module() == self._module

        function_analysis = self._function_analysis[function].get(
            analysis_class)

        if function_analysis is None:
            fam = self._cache_function_analysis_manager.get(function)
            if fam is None:
                fam = FunctionAnalysisManager(self, self._module, function)
                self._cache_function_analysis_manager[function] = fam

            function_analysis = analysis_class()
            function_analysis.initialize(function, fam)
            function_analysis.run_on_function(function, fam)
            self._function_analysis[function][analysis_class] = function_analysis

        return function_analysis

    def get_module(self) -> Module:
        return self._module


class FunctionAnalysisManager(object):
    def __init__(
            self,
            parent: ModuleAnalysisManager,
            module: Module,
            function: Function):
        self._parent = parent
        self._module = module
        self._function = function

    def get_module_analysis(
            self,
            analysis_class: typing.Type[Analysis],
            module: typing.Optional[Module] = None) -> ModuleAnalysis:
        return self._parent.get_module_analysis(analysis_class)

    def get_function_analysis(
            self,
            analysis_class: typing.Type[Analysis],
            function: typing.Optional[Function] = None) -> FunctionAnalysis:
        if function is None:
            function = self._function

        assert isinstance(function, Function)

        return self._parent.get_function_analysis(analysis_class, function)

    def get_module(self) -> Module:
        return self._module

    def get_function(self) -> Function:
        return self._function
