import binaryninja
from binaryninja import (BinaryViewType, MediumLevelILInstruction,
                         MediumLevelILOperation, RegisterValueType,
                         SSAVariable)
from utils.base_tool import safe_str
from function_filters.basic import FunctionType

DestTarget = {
    #D-link
    'lxmldbc_system' : {
        'type'  : FunctionType.FUNC_STR_VARARG,
        'count' : -2,
        'var_idx' : 1,
        'fstr_idx' : 0,
        'p0' : 'in'
    },

    #asuswrt
    'bcmSystemEx' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in',
        'p1' : 'void'
    },

    'INF_system' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 1,
        'p0' : 'in'
    },
    'execve' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'in',
        'p1' : 'in_arr',
        'p2' : 'void'
    },
    'system' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 1,
        'p0' : 'in'
    },
    'execl' : {
        'type'  : FunctionType.FUNC_PURE_VARARG,
        'count' : -2,
        'var_idx' : 0
    },
    'popen' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in',
        'p1' : 'void'
    }
}

def target_has_format_string(item):
    if 'fstr_idx' in item:
        return True
    return False

def target_is_pure_vararg(item):
    if 'var_idx' in item and 'fstr_idx' not in item:
        return True
    return False

def target_read_format_string(item, bv, params):
    if 'fstr_idx' not in item:
        return None
    idx = item['fstr_idx']
    if idx >= len(params):
        return None
    p = params[idx]
    if p.possible_values.type in (
        binaryninja.RegisterValueType.ConstantPointerValue,
        binaryninja.RegisterValueType.ConstantValue
        ):
        v = p.possible_values.value
        s, pos = safe_str(bv, v)
        return s
    return None

def target_get_format_string_index(item):
    return item['fstr_idx']

def target_function_collect_vararg(item, params):
    
    if len(params) > item['var_idx']:
        return params[item['var_idx'] : ]
    
    return []
