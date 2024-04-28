from __future__ import print_function
from binaryninja import *
from binaryninja import MediumLevelILOperation, Function


def is_mem_related(src_ins, dst_ins):
    #src_mem = list()
    index = list()
    for src in src_ins:
        if src.instr.operation == MediumLevelILOperation.MLIL_STORE_SSA:
            #src_mem.append(src)
            index.append(src.function_index)
    for dst in dst_ins:
        if dst.instr.operation == MediumLevelILOperation.MLIL_STORE_SSA:
            if dst.function_index in index:
                return True
    return False


def is_size_related(dst_ins):
    for dst in dst_ins:
        if dst.instr.operation == MediumLevelILOperation.MLIL_IF:
            condition = dst.instr.condition
            if condition.operation != MediumLevelILOperation.MLIL_CMP_E and \
                    condition.operation != MediumLevelILOperation.MLIL_CMP_NE:
                return True
    return False


def safe_asm(bv, asm_str):
    return bv.arch.assemble(asm_str)

def safe_str(bv, offset, max_size=1024):
    try:
        buf = ''
        length = 0
        while max_size > 0:
            ch = bv.read(offset, 1)
            if ch != b'\x00':
                ch = ch.decode("utf-8") 
                buf += ch
                offset += 1
            else:
                return buf, length
            max_size = max_size - 1
            length = length + 1
        return buf, -1
    except Exception as e:
        print(e)
        return None, -1

def safe_bin(bv, offset, size):
    try:
        buf = bv.read(offset, size)
        return buf
    except Exception:
        return None

def get_ssa_def(mlil, var):
    """ Gets the IL that defines var in the SSA form of mlil """
    try:
        return mlil.ssa_form[mlil.ssa_form.get_ssa_var_definition(var)]
    except Exception:
        return None


def gather_defs(il, defs):
    """ Walks up a def chain starting at the given il (mlil-ssa)
    until constants are found, gathering all addresses along the way
    """
    defs.add(il.address)
    op = il.operation

    if op == MediumLevelILOperation.MLIL_CONST:
        return

    if op in [MediumLevelILOperation.MLIL_VAR_SSA_FIELD,
              MediumLevelILOperation.MLIL_VAR_SSA]:
        gather_defs(get_ssa_def(il.function, il.src), defs)

    if op == MediumLevelILOperation.MLIL_VAR_PHI:
        for var in il.src:
            gather_defs(get_ssa_def(il.function, var), defs)

    if hasattr(il, 'src') and isinstance(il.src, MediumLevelILInstruction):
        gather_defs(il.src, defs)


def llil_at(bv, addr):
    funcs = bv.get_functions_containing(addr)
    if funcs is None:
        return None

    return funcs[0].get_low_level_il_at(addr)


def is_call(bv, addr):
    llil = llil_at(bv, addr)
    if llil is None:
        return False

    return llil.operation == LowLevelILOperation.LLIL_CALL


def get_func_containing(bv, addr):
    """ Finds the function, if any, containing the given address """
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs is not None else None

from analysis.utils import get_call_ssa_dest_name
def get_callee_name(bv, instr):
    """ get callee name from instruction
    
    Arguments:
        bv {[type]} -- binaryview
        instr {[type]} -- middle level instruction
    
    Returns:
        [type] -- name
    """
    return get_call_ssa_dest_name(bv, instr)



def calc_format_string(fmt): 
    """calculate args from format string
    
    Arguments:
        fmt {str} -- format string
    
    Returns:
        int -- count
    """
    arg = 0
    i = 0
    while i < len(fmt):
        if fmt[i] == '%':
            if i + 1 < len(fmt) and fmt[i+1] != '%':
                arg += 1
        i += 1
    return arg


def calcNext(var, func : Function):
    """move to the next stack var
    
    Arguments:
        var {[type]} -- current var
        func {Function} -- func
    
    Returns:
        [type] -- [description]
    """
    if not var:
        return None
    if SSAVariable == type(var):
        var = var.var
    try:
        if len(func.stack_layout) - 1 == func.stack_layout.index(var):
            return None
        else:
            return func.stack_layout[func.stack_layout.index(var) + 1]
    except ValueError:
        # For some odd reason BN does screw up the stack layout.. bug?
        return None

def calcVarSize(var, func : Function) -> int:
    """calculate variable size
    
    Arguments:
        var {[type]} -- current var
        func {Function} -- [description]
    
    Returns:
        int -- size of var
    """
    if not var:
        return None
    if isinstance(var, SSAVariable):
        var = var.var
    
    return var.type.width
    

def get_ssa_uses(mlil, var):
    return mlil.ssa_form.get_ssa_var_uses(var)


def gather_uses(il, var_uses, max_depth = -1):
    if il.instr_index in var_uses:
        return
    
    var_uses.add(il.instr_index)

    op = il.operation
    if op == MediumLevelILOperation.MLIL_CONST:
        return
    
    if op == MediumLevelILOperation.MLIL_CALL_SSA:
        return
    
    if op == MediumLevelILOperation.MLIL_SET_VAR_SSA:
        uses = get_ssa_uses(il.function, il.dest)
        for u in uses:
            gather_uses(il.function[u], var_uses)

    if op == MediumLevelILOperation.MLIL_VAR_PHI:
        var = il.dest
        uses = get_ssa_uses(il.function, var)
        for u in uses:
            gather_uses(il.function[u], var_uses)
    
    if hasattr(il, 'dest') and isinstance(il.dest, MediumLevelILInstruction):
        gather_uses(il.dest, var_uses)

def parse_arg_ssa(func : MediumLevelILFunction, var : SSAVariable):
    """SSAVariable without defination
    
    Arguments:
        func {MediumLevelILFunction} -- IR function
        var {SSAVariable} -- ssa variable
    
    Returns:
        [type] -- [description]
    """
    idx = 0
    for p in func.source_function.parameter_vars:
        if p.name == var.var.name:
            return p.name, idx
        idx += 1
    return None, None

    
