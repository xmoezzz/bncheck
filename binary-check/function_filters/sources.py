from binaryninja import (BinaryViewType, MediumLevelILInstruction,
                         MediumLevelILOperation, RegisterValueType,
                         SSAVariable)
from function_filters.basic import FunctionType

SourceTarget = {
    'get_cgi' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret'   : 'out',
    },
    'query_cgi' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret'   : 'out',
    },
    #cgiFormString( char *name, char *result, int max)
    'cgiFormString' : { 
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'in',
        'p1' : 'out',
        'p2' : 'void',
        'ret': 'void'
    },
    'cgiFormStringNoNewlines' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'in',
        'p1' : 'out',
        'p2' : 'void',
        'ret': 'void'
    },
    'cgiFormStringMultiple' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in',
        'p1' : 'out', #char**
        'ret': 'void'
    },
    'cgiFormInteger' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'in',
        'p1' : 'out',
        'p2' : 'in',
        'ret': 'void'
    },
    'cgiFormDouble' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 3,
        'p0' : 'in',
        'p1' : 'out',
        'p2' : 'in',
        'ret': 'void'
    },
    'cgi_get' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret' : 'out'
    },
    'getenv' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret' : 'out'
    },
    #char* FCGX_GetParam (const char *name, FCGX_ParamArray envp)
    'FCGX_GetParam' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 2,
        'p0' : 'in',
        'p1' : 'in',
        'ret': 'out'
    },
    'mg_get_http_var' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : 4,
        'p0' : 'in',
        'p1' : 'in',
        'p2' : 'out',
        'p3' : 'void',
        'ret': 'void'
    },
    'cgi_value' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret' : 'out'
    },
    'cgi_getval' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret' : 'out'
    },
    'webcgi_get' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret' : 'out'
    },
    'websGetVar' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret' : 'out'
    },
    'find_val' : {
        'type'  : FunctionType.FUNC_NORMAL,
        'count' : -1,
        'ret' : 'out'
    }
}

def source_target_check(item, params, output, var):
    solved  = False
    idx     = 0
    for param in params:
        if param.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            p = param.src
            if str(p) == str(var):
                solved = True
                break
        idx += 1
    
    if solved:
        att = 'p{}'.format(idx)
        if att not in item:
            print('%s not exists', att)
            return False
        p = item[att]
        if p == 'out':
            return True
        return False
    
    if len(output) == 0:
        print('output is empty')
        return False
    
    for o in output:
        if str(o) == str(var):
            return True
    return False
    
    