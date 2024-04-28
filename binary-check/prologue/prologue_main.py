from prologue.basic import Module
from analysis.basic import ModuleAnalysisManager
from prologue.phase1_simple_callfix import SimpleCallfixAnalysis


class PrologueManager(object):
    def __init__(self, module:Module):
        assert isinstance(module, Module)

        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = ModuleAnalysisManager(module)
        
    def on_start(self):
        fixer : SimpleCallfixAnalysis = SimpleCallfixAnalysis()
        fixer.on_load(self.__module, self.__mam)


    def on_end(self)->Module:
        del self.__mam
        return self.__get_new_module()
    
    def __get_new_module(self)->Module:
        return self.__module
    
    

