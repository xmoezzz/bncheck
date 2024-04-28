import os
import sys
import pprint

from ctypes import *
from struct import unpack
from analysis.handlers.basic import *

import binaryninja

# mime_handle


class Elf32_MIME_HANDLE_LSB(LittleEndianStructure):
    _fields_ = [
        ("pattern", c_uint),  # ptr
        ("mime_type", c_uint),  # ptr
        ("cache", c_uint),
        ("input", c_uint),  # ptr
        ("output", c_uint),  # ptr
        ("auth", c_uint)
    ]


class Elf32_MIME_HANDLE_MSB(BigEndianStructure):
    _fields_ = [
        ("pattern", c_uint),  # ptr
        ("mime_type", c_uint),  # ptr
        ("cache", c_uint),
        ("input", c_uint),  # ptr
        ("output", c_uint),  # ptr
        ("auth", c_uint)
    ]

# check padding!!!


class Elf64_MIME_HANDLE_LSB(LittleEndianStructure):
    _fields_ = [
        ("pattern", c_longlong),  # ptr
        ("mime_type", c_longlong),  # ptr
        ("cache", c_uint),
        ("input", c_longlong),  # ptr
        ("output", c_longlong),  # ptr
        ("auth", c_uint)
    ]


class Elf64_MIME_HANDLE_MSB(BigEndianStructure):
    _fields_ = [
        ("pattern", c_longlong),  # ptr
        ("mime_type", c_longlong),  # ptr
        ("cache", c_uint),
        ("input", c_longlong),  # ptr
        ("output", c_longlong),  # ptr
        ("auth", c_uint)
    ]


def my_get_data(reader, start, size):
    end = start + size
    reader.seek(start)
    return reader.read(size)


def _parse_mime_handlers_lsb32(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 24)
        entry = Elf32_MIME_HANDLE_LSB.from_buffer_copy(data)
        current_ea = current_ea + 24
        if entry.pattern == 0:
            break
        result.append(entry)
    return result


def _parse_mime_handlers_msb32(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 24)
        entry = Elf32_MIME_HANDLE_MSB.from_buffer_copy(data)
        current_ea = current_ea + 24
        if entry.pattern == 0:
            break
        result.append(entry)
    return result


def _parse_mime_handlers_lsb64(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 40)
        entry = Elf64_MIME_HANDLE_LSB.from_buffer_copy(data)
        current_ea = current_ea + 40
        if entry.pattern == 0:
            break
        result.append(entry)
    return result


def _parse_mime_handlers_msb64(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 40)
        entry = Elf64_MIME_HANDLE_MSB.from_buffer_copy(data)
        current_ea = current_ea + 40
        if entry.pattern == 0:
            break
        result.append(entry)
    return result


def parse_mime_handlers(reader, ea, seg_end, bitness, endianness):
    result = None
    if endianness == binaryninja.enums.Endianness.LittleEndian:
        if bitness == 32:
            result = _parse_mime_handlers_lsb32(reader, ea, seg_end)
        elif bitness == 64:
            result = _parse_mime_handlers_lsb64(reader, ea, seg_end)
    else:
        if bitness == 32:
            result = _parse_mime_handlers_msb32(reader, ea, seg_end)
        elif bitness == 64:
            result = _parse_mime_handlers_msb64(reader, ea, seg_end)
    return result


def read_cstring(api, ea, max=260):
    cur_byte = 0
    max_byte = max
    current_str = str()
    while cur_byte < max_byte:
        now_byte = my_get_data(api, ea + cur_byte, 1)
        if now_byte == '\x00':
            break
        current_str = current_str + now_byte
        cur_byte = cur_byte + 1
    return current_str


def safe_encode_to_bytes(name):
    if isinstance(name, unicode):
        return name.encode('utf8')
    return name


def process_macro_httpd_internal(bv):
    function_map = dict()
    result = None

    syms = bv.symbols
    if 'mime_handlers@GOT' not in syms:
        return None

    handler_sym = syms['mime_handlers@GOT']
    if handler_sym.type != binaryninja.enums.SymbolType.DataSymbol:
        return None

    handler_address = handler_sym.address
    print('symbol address ptr: %x' % handler_address)

    reader = binaryninja.BinaryReader(bv)
    arch = bv.arch.name
    bitness = 32

    if arch in ('x86_64', 'aarch64'):
        bitness = 64

    reader.seek(handler_address)
    handler = -1
    if bitness == 32:
        handler = reader.read32()
    else:
        handler = reader.read64()

    print('handler : %x' % handler)
    seg = bv.get_segment_at(handler)
    if seg is None:
        return None

    result = parse_mime_handlers(
        reader,
        handler,
        seg.end,
        bitness,
        bv.endianness)
    if result:
        real_result = list()
        for entry in result:
            item = dict()
            try:
                item['pattern'] = '%x' % entry.pattern
                item['mime_type'] = '%x' % entry.mime_type
                item['cache'] = entry.cache
                item['input'] = 'sub_%x' % entry.input
                item['output'] = 'sub_%x' % entry.output
                item['input_addr'] = entry.input
                item['output_addr'] = entry.output
                item['auth'] = entry.auth

                ##
                item['pattern_str'] = read_cstring(reader, entry.pattern)
                item['mime_type_str'] = read_cstring(reader, entry.mime_type)
            except BaseException:
                pass
            real_result.append(item)
        return real_result
    # pprint.pprint(real_result)
    return []


def process_macro_httpd(bv):
    result = process_macro_httpd_internal(bv)
    if len(result) == 0:
        return []
    handlerItems = []
    for item in result:
        auth = AuthType.AUTH_ENABLE
        if not item['auth']:
            auth = AuthType.AUTH_DISABLE
        currentItem = HandlerItem.make(auth, item['output_addr'])
        handlerItems.append(currentItem)
    return handlerItems
