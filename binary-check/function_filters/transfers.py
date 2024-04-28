import binaryninja

from binaryninja import (BinaryViewType, MediumLevelILInstruction,
                         MediumLevelILOperation, RegisterValueType,
                         SSAVariable)
from utils.base_tool import safe_str
from function_filters.basic import FunctionType

TaintSource = {
    'sprintf' : {
        'type'  : FunctionType.FUNC_STR_VARARG,
        'count' : -2,
        'var_idx' : 2,
        'fstr_idx' : 1,
        'p0' : 'out',
        'p1' : 'in',
        'ret': 'void'
    },
    'sprintf_s' : {
        'type'  : FunctionType.FUNC_STR_VARARG,
        'count' : -2,
        'var_idx' : 3,
        'fstr_idx' : 2,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in',
        'ret': 'void'
    },
    'snprintf': {
        'type'  : FunctionType.FUNC_STR_VARARG,
        'count' : -2,
        'var_idx' : 3,
        'fstr_idx' : 2,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in',
        'ret': 'void'
    },
    'snprintf_s' : {
        'type'  : FunctionType.FUNC_STR_VARARG,
        'count' : -2,
        'var_idx' : 3,
        'fstr_idx' : 2,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in',
        'ret': 'void'
    },
    '__sprintf_chk' : {
        'type'  : FunctionType.FUNC_STR_VARARG,
        'count' : -2,
        'var_idx' : 4,
        'fstr_idx' : 3,
        'p0' : 'out',
        'p1' : 'void',
        'p2' : 'void',
        'p3' : 'in',
        'ret' : 'void'
    },
    'strcpy' :  {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'out',
        'p1' : 'in_full',
        'ret': 'out'
    },
    'strcpy_s' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in_full',
        'ret': 'out'
    },
    'strncpy' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in_full',
        'ret': 'out'
    },
    'strncpy_s' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 4,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in_full',
        'p3' : 'in',
        'ret': 'out'
    },
    'memcpy' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in_full',
        'ret': 'out'
    },
    'memcpy_s' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 4,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in_full',
        'p3' : 'in',
        'ret': 'out'
    },
    'strdup' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 1,
        'p0' : 'in_full',
        'ret': 'out'
    },
    'strndup' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in_full',
        'p1' : 'in',
        'ret': 'out'
    },
    'strcat' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'out',
        'p1' : 'in_full',
        'ret': 'out'
    },
    'strncat' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'out',
        'p1' : 'in_full',
        'p2' : 'in',
        'ret': 'out'
    },
    'memmove' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'out',
        'p1' : 'in_full',
        'p2' : 'in',
        'ret': 'out'
    },
    'memmove_s' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 4,
        'p0' : 'out',
        'p1' : 'in',
        'p2' : 'in_full',
        'p3' : 'in',
        'ret': 'out'
    },
    'strchr' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in_full',
        'p1' : 'in',
        'ret': 'out'
    },
    'memchr' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in_full',
        'p1' : 'in',
        'p2' : 'in',
        'ret': 'out'
    },
    'strrchr' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in_full',
        'p1' : 'in',
        'ret': 'out'
    },
    'strpbrk' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in_full',
        'p1' : 'in',
        'ret': 'out'
    },
    'strstr' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in_full',
        'p1' : 'in',
        'ret': 'out'
    },
    'strtok' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in_full',
        'p1' : 'in',
        'ret': 'out'
    },
    'safe_asprintf' : {
        'type'  : FunctionType.FUNC_STR_VARARG,
        'count' : -2,
        'var_idx' : 2,
        'fstr_idx' : 1,
        'p0' : 'out',
        'p1' : 'in',
        'ret': 'void'
    }
}

def TaintFunctionChecker(item, params, output):
    '''
    trace input soucres
    '''
    solved = False
    idx = 0
    sources = []
    
    if 'var_idx' in item:
        idx = item['var_idx']
        if len(params) > idx:
            while idx < len(params):
                sources.append(params[idx])
                idx += 1
        idx = 0
        while idx < item['var_idx']:
            att = 'p{}'.format(idx)
            if item[att] == 'in_full' and idx < len(params):
                sources.append(params[idx])
            idx += 1
    
    return sources

def has_format_string(item):
    if 'fstr_idx' in item:
        return True
    return False

def read_format_string(item, bv, params):
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