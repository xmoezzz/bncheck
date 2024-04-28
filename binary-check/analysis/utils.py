
from binaryninja import (BinaryView, BinaryViewType, MediumLevelILInstruction,
                         MediumLevelILOperation, RegisterValueType,
                         SSAVariable, BinaryReader, Symbol, Function, Variable)

from binaryninja.enums import Endianness
import operator
from .basic import Module
import typing
from collections import defaultdict
import itertools


def get_ascii_string_at(
        bv: BinaryView,
        address: int,
        require_cstring=True) -> typing.Optional[str]:
    """
    return the string starts from address, return str(not bytes), may return None.
    """
    binary_reader = BinaryReader(bv)
    binary_reader.seek(address)

    byte_u8: int = binary_reader.read8()
    assert isinstance(byte_u8, int)

    byte_sequence: typing.List[int] = []
    while byte_u8 is not None and byte_u8 > 0 and byte_u8 <= 0x7f:
        byte_sequence.append(byte_u8)
        byte_u8 = binary_reader.read8()
    if byte_u8 != 0:
        return None
    return bytes(byte_sequence).decode("ASCII")


def get_bytes_at(
        bv: BinaryView,
        address: int,
        size: int) -> typing.Optional[str]:
    """
    return the string starts from address, return str(not bytes), may return None.
    """
    assert size > 0
    binary_reader = BinaryReader(bv)
    binary_reader.seek(address)

    byte_u8: int = binary_reader.read8()
    assert isinstance(byte_u8, int)  # we must make some errors

    byte_sequence: typing.List[int] = []
    while True:
        byte_sequence.append(byte_u8)
        if len(byte_sequence) >= size:
            break

        byte_u8 = binary_reader.read8()
        if byte_u8 is None:
            return None
    return bytes(byte_sequence)


def is_ssa_var_argumuent(ssa_var: SSAVariable) -> bool:
    assert isinstance(ssa_var, SSAVariable)
    assert ssa_var.version is not None
    if ssa_var.version != 0:
        return False
    var = ssa_var
    func = var.function
    parameter_var_list: typing.List[Variable] = func.parameter_vars.vars
    return var in parameter_var_list


def get_call_ssa_dest_name(
        module: Module,
        inst: MediumLevelILInstruction) -> typing.Optional[str]:
    assert inst.operation in [
        MediumLevelILOperation.MLIL_CALL_SSA,
        MediumLevelILOperation.MLIL_TAILCALL_SSA]

    addr = get_call_ssa_dest_addr(module, inst)
    if addr is None:
        return None
    symbol = module.get_symbol_at(addr)
    if symbol is not None:
        #fix postfix
        return symbol.short_name
    return None


def get_call_ssa_dest_addr(
        module: Module,
        inst: MediumLevelILInstruction) -> typing.Optional[int]:
    """
    内部函数。。。
    """
    assert inst.operation in [
        MediumLevelILOperation.MLIL_CALL_SSA,
        MediumLevelILOperation.MLIL_TAILCALL_SSA]
    if inst.dest.operation in [
            MediumLevelILOperation.MLIL_CONST,
            MediumLevelILOperation.MLIL_CONST_PTR]:
        return inst.dest.constant
    elif inst.dest.operation in [MediumLevelILOperation.MLIL_IMPORT]:
        byte_sequence = get_bytes_at(
            module, inst.dest.constant, inst.dest.size)
        if byte_sequence is None:
            return None
        assert len(byte_sequence) in [4, 8]

        assert module.endianness in [
            Endianness.BigEndian,
            Endianness.LittleEndian]

        ptr = 0
        if module.endianness == Endianness.LittleEndian:
            for v in byte_sequence[::-1]:
                ptr *= 256
                ptr += v
        else:
            for v in byte_sequence:
                ptr *= 256
                ptr += v
        return ptr
    else:
        return None


def get_func_call_ssa_instructions_to(module: Module,
                                      function: Function,
                                      name_or_addr: typing.Union[str,
                                                                 int]) -> typing.List[MediumLevelILInstruction]:
    """返回进程内所有调用这个函数的call ir指令

    Arguments:
        function {Module} -- [description]
        name_or_addr {typing.Union[str, int]} -- [description]

    Returns:
        typing.List[MediumLevelILInstruction] -- [description]
    """
    assert isinstance(name_or_addr, (str, int))
    if isinstance(name_or_addr, str):
        name: str = name_or_addr
        symbols: typing.List[Symbol] = module.get_symbols_by_name(name)
        target_addrs: typing.Set[int] = set(
            map(lambda symbol: symbol.address, symbols))
    else:
        target_addrs = set([name_or_addr])

    retv: typing.List[MediumLevelILInstruction] = []

    for blk in function.mlil.ssa_form:
        for insn in blk:
            if insn.operation in (MediumLevelILOperation.MLIL_CALL_SSA,
                                  MediumLevelILOperation.MLIL_TAILCALL_SSA):
                if insn.address in target_addrs:
                    retv.append(insn)
                elif insn.dest.operation in [MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR]:
                    if insn.dest.constant in target_addrs:
                        retv.append(insn)
                elif insn.dest.operation in [MediumLevelILOperation.MLIL_IMPORT]:
                    byte_sequence = get_bytes_at(
                        module, insn.dest.constant, insn.dest.size)
                    if byte_sequence is not None:
                        assert len(byte_sequence) in [4, 8]

                        assert module.endianness in [
                            Endianness.BigEndian, Endianness.LittleEndian]

                        ptr = 0
                        if module.endianness == Endianness.LittleEndian:
                            for v in byte_sequence[::-1]:
                                ptr *= 256
                                ptr += v
                        else:
                            for v in byte_sequence:
                                ptr *= 256
                                ptr += v

                        if ptr in target_addrs:
                            retv.append(insn)
    return retv


def get_call_ssa_instructions_to(module: Module,
                                 name_or_addr: typing.Union[str,
                                                            int]) -> typing.List[MediumLevelILInstruction]:
    """
    返回调用name函数的call命令
    """
    assert isinstance(name_or_addr, (str, int))
    if isinstance(name_or_addr, str):
        name: str = name_or_addr
        symbols: typing.List[Symbol] = module.get_symbols_by_name(name)
        target_addrs: typing.Set[int] = set(
            map(lambda symbol: symbol.address, symbols))
    else:
        target_addrs = set([name_or_addr])

    retv: typing.List[MediumLevelILInstruction] = []

    function_to_calladdress: typing.DefaultDict[Function, int] = defaultdict(
        set)

    addr: int
    for addr in target_addrs:
        for caller in module.get_callers(addr):
            caller_addr: int = caller.address
            caller_function: Function = caller.function
            if caller_function is None:
                continue
            assert caller_addr is not None
            assert isinstance(caller_addr, int)

            function_to_calladdress[caller_function].add(caller_addr)

        for caller in module.get_code_refs(addr):
            caller_addr: int = caller.address
            caller_function: Function = caller.function
            if caller_function is None:
                continue
            assert caller_addr is not None
            assert isinstance(caller_addr, int)

            if caller_function not in function_to_calladdress:
                function_to_calladdress[caller_function] = set()
            #function_to_calladdress[caller_function].add(caller_addr)
            #这里不加入function_to_calladdress的原因是， caller_addr可能是函数指针如 create_thread(thread_main),这种时候，thread_main的code_refs可能会落在当前指令上

    for func, addrs in function_to_calladdress.items():
        if func.mlil.ssa_form is None:
            continue
        inst: MediumLevelILInstruction
        for inst in func.mlil.ssa_form.instructions:
            if inst.operation in [
                    MediumLevelILOperation.MLIL_CALL_SSA,
                    MediumLevelILOperation.MLIL_TAILCALL_SSA]:
                if inst.address in addrs:
                    retv.append(inst)
                elif inst.dest.operation in [MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR]:
                    if inst.dest.constant in target_addrs:
                        retv.append(inst)
                elif inst.dest.operation in [MediumLevelILOperation.MLIL_IMPORT]:
                    byte_sequence = get_bytes_at(
                        module, inst.dest.constant, inst.dest.size)
                    if byte_sequence is not None:
                        assert len(byte_sequence) in [4, 8]

                        assert module.endianness in [
                            Endianness.BigEndian, Endianness.LittleEndian]

                        ptr = 0
                        if module.endianness == Endianness.LittleEndian:
                            for v in byte_sequence[::-1]:
                                ptr *= 256
                                ptr += v
                        else:
                            for v in byte_sequence:
                                ptr *= 256
                                ptr += v

                        if ptr in target_addrs:
                            retv.append(inst)

    return retv


COMMON_BINARY_MEDIUM_LEVEL_IL_OPERATION_TO_OPERATOR = {
    MediumLevelILOperation.MLIL_ADD: operator.add,
    MediumLevelILOperation.MLIL_SUB: operator.sub,
    MediumLevelILOperation.MLIL_MUL: operator.mul,
    MediumLevelILOperation.MLIL_DIVU: operator.floordiv,
    # MediumLevelILOperation.MLIL_DIVS: operator.floordiv,
    MediumLevelILOperation.MLIL_AND: operator.and_,
    MediumLevelILOperation.MLIL_OR: operator.or_,
    MediumLevelILOperation.MLIL_XOR: operator.xor,
    MediumLevelILOperation.MLIL_LSL: operator.lshift,
    MediumLevelILOperation.MLIL_LSR: operator.rshift,
}

COMMON_UNARY_MEDIUM_LEVEL_IL_OPERATION_TO_OPERATOR = {
    MediumLevelILOperation.MLIL_NOT: operator.not_,
    MediumLevelILOperation.MLIL_NEG: operator.neg,
}
