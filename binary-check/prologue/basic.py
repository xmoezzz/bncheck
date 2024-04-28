import binaryninja
import abc

from binaryninja.binaryview import BinaryView as Module
from binaryninja.function import Function
from analysis.basic import ModuleAnalysisManager


class PrologueAnalysis(abc.ABC):

    @abc.abstractmethod
    def on_load(self, module:Module, mam:ModuleAnalysisManager):
        pass

    @abc.abstractmethod
    def require_restart(self) -> bool:
        """return True if analyzer requires reanalysis
        
        Returns:
            bool -- [description]
        """
        pass

