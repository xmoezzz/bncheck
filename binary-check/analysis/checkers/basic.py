from ..basic import ModuleAnalysis, Module, Function, ModuleAnalysisManager
import typing
import abc


class CheckerBase(ModuleAnalysis, abc.ABC):
    """
    checker must be an module analysis
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__result = []

    def report(self, result):
        self.__result.append(result)

    def get_reports(self) -> typing.List:
        return self.__result
    
    @abc.abstractstaticmethod
    def get_checker_name()->str:
        pass

