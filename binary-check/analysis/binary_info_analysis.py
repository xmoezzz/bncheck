import enum
import subprocess
import re
import os
import tempfile
import base64
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from binaryninja import RegisterValueType, MediumLevelILOperation

from utils.base_tool import *
from analysis.basic import ModuleAnalysis, AnalysisManager, Module, ModuleAnalysisManager
from analysis.ircall_analysis import IRCallsAnalysis


class LibcType(enum.Enum):
    LIBC_UNKNOWN = 0,
    LIBC_GLIBC = 1,
    LIBC_UCLIBC = 2


class RelroType(enum.Enum):
    FULLY_ENABLE = 0,
    PART_ENABLE = 1,
    DISABLE = 2


class PieType(enum.Enum):
    DSO = 0,
    ENABLE = 1,
    DISABLE = 2,
    INVALID = 3


class SymbolTab(object):
    def __init__(self, addr, name, size):
        self.addr = addr
        self.name = name
        self.size = size


class StringCache(object):
    def __init__(self):
        self.buf = None
        self.length = 0
        self.start = 0
        self.symbol = None
        self.good = True

    def __str__(self):
        return "<StringCache : buf = %s, len = %s, start = %x, symbol = %s, good = %s>" % (
            self.buf, str(self.length), self.start, self.symbol, str(self.good))


class DataCache(object):
    def __init__(self):
        self.buf = None
        self.length = 0
        self.start = 0
        self.symbol = None

    def __str__(self):
        tmp_buf = None
        if self.buf is not None:
            tmp_buf = base64.b64encode(self.buf)

        return "<DataCache : base64buf = %s, len = %s, start = %x, symbol = %s>" % (
            tmp_buf, self.length, self.start, self.symbol)


class ConstantRefReportItem(object):
    def __init__(self):
        '''
        binaryninja.mediumlevelil.MediumLevelILFunction object
        '''
        self.function = None
        '''
        str (strcmp, ...)
        '''
        self.callee = None
        '''
        param (binaryninja.mediumlevelil.MediumLevelILInstruction)
        '''
        self.param = None
        '''
        param index
        '''
        self.param_idx = None
        '''
        StringCache
        '''
        self.cmp_str = None
        '''
        DataCache
        '''
        self.cmp_data = None
        self.is_cmp_str = True
        self.function_offset = None

    def __str__(self):
        if self.is_cmp_str:
            return "<ConstantRefReportItem : function = %s, callee = %s, param = %s, idx = %s, str = %s, offset = %s>" % (
                self.function, self.callee, self.param, self.param_idx, self.cmp_str, self.function_offset)
        else:
            return "<ConstantRefReportItem : function = %s, callee = %s, param = %s, idx = %s, data = %s, offset = %s>" % (
                self.function, self.callee, self.param, self.param_idx, self.cmp_data, self.function_offset)

    @staticmethod
    def make_with_str(
            function,
            callee,
            param,
            param_idx,
            cmp_str,
            function_offset):
        item = ConstantRefReportItem()
        item.function = function
        item.callee = callee
        item.param = param
        item.param_idx = param_idx
        item.cmp_str = cmp_str
        item.is_cmp_str = True
        item.function_offset = function_offset

        return item

    @staticmethod
    def make_with_data(
            function,
            callee,
            param,
            param_idx,
            cmp_data,
            function_offset):
        item = ConstantRefReportItem()
        item.function = function
        item.callee = callee
        item.param = param
        item.param_idx = param_idx
        item.cmp_data = cmp_data
        item.is_cmp_str = False
        item.function_offset = function_offset

        return item


def process_strcmp(bv, insn, cache, symtab):
    if len(insn.params) < 2:
        return None

    arg1 = insn.params[0]
    arg2 = insn.params[1]

    arg1_value = None
    arg2_value = None
    if arg1.possible_values.type in (
        RegisterValueType.ConstantPointerValue,
        RegisterValueType.ConstantValue
    ):
        arg1_value = arg1.possible_values.value

    if arg2.possible_values.type in (
        RegisterValueType.ConstantPointerValue,
        RegisterValueType.ConstantValue
    ):
        arg2_value = arg2.possible_values.value

    if arg1_value is not None and arg2_value is not None:
        return None

    if arg1_value is not None or arg2_value is not None:
        param_idx = 1
        arg = arg1
        cur_val = arg1_value

        if arg2_value is not None:
            param_idx = 2
            arg = arg2
            cur_val = arg2_value

        string_item = None

        if cur_val in cache:
            string_item = cache[cur_val]
        else:
            cur_buf, cur_len = safe_str(bv, arg)
            string_item = StringCache()
            string_item.length = cur_len
            string_item.buf = cur_buf
            string_item.start = cur_val

            if cur_len == -1:
                string_item.good = False

            if string_item.start in symtab:
                string_item.symbol = symtab[string_item.start].name
                if not string_item.good:
                    string_item.length = symtab[string_item.start].size
                    string_item.good = True

        return ConstantRefReportItem.make_with_str(
            insn.function, 'strcmp', arg, param_idx, string_item, insn.address)
    return None


def process_memcmp(bv, insn, cache, symtab):
    if len(insn.params) < 3:
        return None

    result = None

    arg1 = insn.params[0]
    arg2 = insn.params[1]

    arg1_value = None
    arg2_value = None
    if arg1.possible_values.type in (
        RegisterValueType.ConstantPointerValue,
        RegisterValueType.ConstantValue
    ):
        arg1_value = arg1.possible_values.value

    if arg2.possible_values.type in (
        RegisterValueType.ConstantPointerValue,
        RegisterValueType.ConstantValue
    ):
        arg2_value = arg2.possible_values.value

    if arg1_value is not None and arg2_value is not None:
        return None

    if arg1_value is not None or arg2_value is not None:
        param_idx = 1
        arg = arg1
        cur_val = arg1_value

        if arg2_value is not None:
            param_idx = 2
            arg = arg2
            cur_val = arg2_value

        if cur_val in cache:
            string_item = cache[cur_val]

            if string_item.start in symtab:
                string_item.symbol = symtab[string_item.start].name

            result = ConstantRefReportItem.make_with_str(
                insn.function, 'memcmp', arg, param_idx, string_item, insn.address)
        else:
            cur_buf, cur_len = safe_str(bv, arg)
            string_item = StringCache()
            string_item.length = cur_len
            string_item.buf = cur_buf
            string_item.start = cur_val

            if cur_val in symtab:
                data_item = DataCache()
                data_item.start = cur_val
                data_item.length = symtab[string_item.start].size
                data_item.buf = safe_bin(bv, cur_val, data_item.length)
                string_item.symbol = symtab[string_item.start].name

                result = ConstantRefReportItem.make_with_data(
                    insn.function, 'memcmp', arg, param_idx, string_item, insn.address)
            else:
                data_item = DataCache()
                data_item.start = cur_val
                data_item.length = -1

                result = ConstantRefReportItem.make_with_data(
                    insn.function, 'memcmp', arg, param_idx, string_item, insn.address)

    return result


compare_funcs = {
    'strcmp': process_strcmp,
    'memcmp': process_memcmp
}


class BinaryInfoAnalysis(ModuleAnalysis):
    def __init__(self, *args, **kwargs):
        super(BinaryInfoAnalysis, self).__init__(*args, *kwargs)
        #self.const_ref_results = []

    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        #aa = mam.get_module_analysis(IRCallsAnalysis, module)
        #self.calls   = aa.get_ir_calls()
        self._iself = False
        self._symtab = {}
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "elf")
            module.save(path)
            try:
                with open(path, "rb") as f:
                    elf = ELFFile(f)
                    for section in elf.iter_sections():
                        if not isinstance(section, SymbolTableSection):
                            continue
                        for symbol in section.iter_symbols():
                            addr = symbol.entry['st_value']
                            size = symbol.entry['st_size']
                            self._symtab[addr] = SymbolTab(
                                addr, symbol.name, size)
            except BaseException:
                pass

            with open(path, "rb") as f:
                self._data = f.read()
            try:
                self._readelf_result = subprocess.check_output(
                    ["readelf", "-W", "-l", "-d", "-s", "-h", path]).decode("utf-8")
            except subprocess.CalledProcessError:
                self._readelf_result = ""

        cache = {}
        for string_item in module.strings:
            buf = module.read(string_item.start, string_item.length)
            item = StringCache()
            item.start = string_item.start
            item.length = string_item.length
            item.buf = buf
            cache[string_item.start] = item
        """
        for insn in self.calls:
            if insn.operation not in (
                MediumLevelILOperation.MLIL_CALL_SSA,
                MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
                MediumLevelILOperation.MLIL_TAILCALL_SSA
                ):
                continue

            name = get_callee_name(module, insn)
            if name is None or name not in compare_funcs:
                continue

            result = compare_funcs[name](module, insn, cache)
            if not result is None:
                self.const_ref_results.append(result)
        """

    def file_is_elf(self) -> bool:
        return self._iself

    def get_symtab(self) -> dict:
        return self._symtab

    # def get_const_ref(self) -> list:
    #    return self.const_ref_results

    def get_relro_type(self) -> RelroType:
        if re.search(r'GNU_RELRO', self._readelf_result):
            if re.search(r'BIND_NOW', self._readelf_result):
                return RelroType.FULLY_ENABLE
            else:
                return RelroType.PART_ENABLE
        else:
            return RelroType.DISABLE

    def is_fortify_source_enabled(self) -> bool:
        if re.search(r'_chk', self._readelf_result):
            return True
        else:
            return False

    def get_pie_type(self) -> PieType:
        if re.search(r'Type:\s*EXEC', self._readelf_result):
            return PieType.DISABLE
        elif re.search(r'Type:\s*DYN', self._readelf_result):
            if re.search(r'\(DEBUG\)', self._readelf_result):
                return PieType.ENABLE
            else:
                return PieType.DSO
        else:
            return PieType.INVALID

    def is_nx_enabled(self) -> bool:
        nx_off = re.search(r'GNU_STACK[\s0-9a-z]*RWE', self._readelf_result)
        if nx_off is None:
            return True
        else:
            return False

    def is_stack_canary_enabled(self) -> bool:
        canary_on = re.search(r'__stack_chk_fail', self._readelf_result)
        if canary_on is None:
            return True
        else:
            return False

    def get_compiler_settings_dict(self) -> dict:
        """
        this method will return a dict
        """

        dict_res = {}
        dict_res["PIE"] = self.get_pie_type()
        dict_res["NX"] = self.is_nx_enabled()
        dict_res["Canary"] = self.is_stack_canary_enabled()
        dict_res["RELRO"] = self.get_relro_type()
        dict_res["FORTIFY_SOURCE"] = self.is_fortify_source_enabled()

        return dict_res

    def get_libc_type(self):
        data = self._data
        if b'__uClibc_start_main' in data:
            return LibcType.LIBC_UCLIBC
        if b'__libc_start_main' in data:
            return LibcType.LIBC_GLIBC
        return LibcType.LIBC_UNKNOWN
