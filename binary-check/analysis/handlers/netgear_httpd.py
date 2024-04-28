from __future__ import print_function

import os
import sys
import pprint
#import BnSetup

from ctypes import *
from struct import unpack
from analysis.handlers.basic import *

import binaryninja


# mime_handle
class Elf32_MIME_HANDLE_LSB(LittleEndianStructure):
    _fields_ = [
        ("cginame", c_uint),  # ptr
        ("function", c_uint),  # ptr
    ]


class Elf32_MIME_HANDLE_MSB(BigEndianStructure):
    _fields_ = [
        ("cginame", c_uint),  # ptr
        ("function", c_uint),  # ptr
    ]

# check padding!!!


class Elf64_MIME_HANDLE_LSB(LittleEndianStructure):
    _fields_ = [
        ("cginame", c_longlong),  # ptr
        ("function", c_longlong),  # ptr
    ]


class Elf64_MIME_HANDLE_MSB(BigEndianStructure):
    _fields_ = [
        ("cginame", c_longlong),  # ptr
        ("function", c_longlong),  # ptr
    ]


def my_get_data(reader, start, size):
    end = start + size
    reader.seek(start)
    return reader.read(size)


def _parse_mime_handlers_lsb32(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 8)
        entry = Elf32_MIME_HANDLE_LSB.from_buffer_copy(data)
        current_ea = current_ea + 8
        if entry.cginame == 0:
            break
        result.append(entry)
    return result


def _parse_mime_handlers_msb32(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 8)
        entry = Elf32_MIME_HANDLE_MSB.from_buffer_copy(data)
        current_ea = current_ea + 8
        if entry.cginame == 0:
            break
        result.append(entry)
    return result


def _parse_mime_handlers_lsb64(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 16)
        entry = Elf64_MIME_HANDLE_LSB.from_buffer_copy(data)
        current_ea = current_ea + 16
        if entry.cginame == 0:
            break
        result.append(entry)
    return result


def _parse_mime_handlers_msb64(reader, ea, seg_end):
    result = list()
    current_ea = ea
    while current_ea < seg_end:
        data = my_get_data(reader, current_ea, 16)
        entry = Elf64_MIME_HANDLE_MSB.from_buffer_copy(data)
        current_ea = current_ea + 16
        if entry.cginame == 0:
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


def process_netgear_httpd_internal(bv):
    function_map = dict()
    result = None

    syms = bv.symbols
    if 'mimeCommandHandlers@GOT' not in syms:
        return None

    handler_sym = syms['mimeCommandHandlers@GOT']
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
                item['cginame'] = entry.cginame
                item['function'] = entry.function
                ##
                item['cginame_str'] = read_cstring(reader, entry.cginame)
            except BaseException:
                pass
            real_result.append(item)

        # pprint.pprint(real_result)
        return real_result

    return []


def process_netgear_httpd(bv):
    result = process_netgear_httpd_internal(bv)
    if len(result) == 0:
        return []
    handlerItems = []
    for item in result:
        auth = AuthType.AUTH_UNKNOWN
        currentItem = HandlerItem.make(auth, item['function'])
        currentItem.symbol = item['cginame_str']
        handlerItems.append(currentItem)
    return handlerItems
