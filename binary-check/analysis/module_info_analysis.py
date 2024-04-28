from analysis.basic import Module, Function, ModuleAnalysis, ModuleAnalysisManager
from collections import defaultdict

import os
import sys
import logging

logger = logging.getLogger(__file__)

_parent_dir = os.path.dirname(os.path.abspath(__file__))
sys.path = [
    os.path.join(
        _parent_dir,
        '../version_scan/version-scan')] + sys.path

enable_version_scan = False

try:
    import server
except ImportError:
    logger.error('Unable to import server from version-scan')
    enable_version_scan = True


class ModuleInfoAnalysis(ModuleAnalysis):
    """我们需要version-scan来初始化这部分数据
       如果从参数中没有提供version-scan传过来的数据，
       那么需要跑一次内置的version-scan (可禁止)

    Arguments:
        ModuleAnalysis {[type]} -- [description]
    """

    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        """entries[lib] = set(versions)
        """
        self.entries = defaultdict(set)
        self.inited = False

    def init_by_version_scan_data(self, json_data):
        if self.inited:
            return
        self.__parse_data(json_data)
    
    def is_built_in(self)->bool:
        return enable_version_scan

    def init_by_running_version_scan(self, filename: str):
        """need submodule
        """
        if self.inited:
            return

        if not enable_version_scan:
            return
        if filename.endswith('.bndb'):
            return
        data = server.version_scan(
            filename, 'stdout', None, None, "bn:infoleak:extra")
        if data is None or len(data) == 0:
            return
        self.__parse_data(data)

    def __parse_data(self, data)->bool:
        try:
            if "libs" not in data:
                return
            libs_entry = data["libs"]
            for sub_lib_entry in libs_entry:
                if "libs" not in sub_lib_entry:
                    continue
                item = sub_lib_entry["libs"]
                self.entries[item["lib"]].add(item["version"])
            return True
        except Exception as e:
            logger.warning("failed to parse version data")
            return False


    def all_libraries(self):
        retv = []
        for k, _ in self.entries.items():
            retv.append(k)
        return retv

    def full_data(self):
        return self.entries
