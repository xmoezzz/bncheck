from analysis.basic import Module, Function, ModuleAnalysis, ModuleAnalysisManager
from binaryninja import MediumLevelILInstruction, MediumLevelILOperation
from analysis.module_info_analysis import ModuleInfoAnalysis

import binaryninja
import typing

from analysis.handlers.basic import HandlerItem, AuthType
from analysis.handlers.macro_httpd import process_macro_httpd
from analysis.handlers.netgear_httpd import process_netgear_httpd

dispatcher_handlers = {
    "macro_httpd": process_macro_httpd,
    "netgear_httpd": process_netgear_httpd
}


class FunctionInfoAnalysis(ModuleAnalysis):
    """主要为一些httpd获取dispatcher信息

    Arguments:
        FunctionAnalysis {[type]} -- [description]
    """

    def run_on_module(self, module: Function, mam: ModuleAnalysisManager):
        self.__module_analysis: ModuleInfoAnalysis = mam.get_module_analysis(
            ModuleInfoAnalysis)
        self.__all_handlers: typing.Dict[str, list] = dict()
        self.__all_auth_handlers: typing.Dict[str, list] = dict()
        self.__all_unauth_handlers: typing.Dict[str, list] = dict()
        assert self.__module_analysis is None

        libraries = set(self.__module_analysis.all_libraries())
        for name, handler in dispatcher_handlers.items():
            if name not in libraries:
                continue
            handler_item = handler(module)
            self.__all_handlers[name] = handler_item

        self.__all_unauth_handlers, self.__all_auth_handlers = self.__gen_handlers()

    def all_handlers(self):
        return self.__all_handlers

    def __gen_handlers(self):
        retm = dict()
        retm_c = dict()
        for k, vv in self.__all_handlers.items():
            disabled = []
            enabled = []
            for v in vv:
                if v.auth == AuthType.AUTH_DISABLE:
                    disabled.append(v)
                elif v.auth == AuthType.AUTH_ENABLE:
                    enabled.append(v)
            if len(disabled):
                retm[k] = disabled
            if len(enabled):
                retm_c[k] = enabled
        return retm, retm_c

    def all_unauth_handlers(self):
        return self.__all_unauth_handlers

    def all_auth_handlers(self):
        return self.__all_auth_handlers
