import enum
import typing

class FunctionType(enum.IntEnum):
    """常规函数，固定参数个数
    """
    FUNC_NORMAL = 0,
    """变参, 但是是fmt string控制的
    """
    FUNC_STR_VARARG = 1,
    """变参, 纯变参
    """
    FUNC_PURE_VARARG = 2

class FunctionParameterType(enum.IntEnum):
    P_IN   = 0,
    P_OUT  = 1,
    """不关心参数的种类，但是不代表这里就是空的
    """
    P_VOID   = 2,
    P_INARR  = 3,
    P_OUTARR = 4

class FunctionReturnType(enum.IntEnum):
    R_OUT  = 0,
    """不关心返回值，但是不代表这个函数调用没有返回值
    """
    R_VOID = 1


class FunctionPrototype(object):
    def __init__(self, name : str, func_type : FunctionType):
        assert isinstance(name, str)
        assert isinstance(func_type, FunctionType)
        self.__name : str = name
        self.__func_type : FunctionType = func_type
        self.__initialized = False
    
    def initialize(self, item : dict):
        self.__count = item['count']
        if self.__func_type == FunctionType.FUNC_STR_VARARG:
            self.__var_idx = item['var_idx']
            self.__fstr_idx = item['fstr_idx']
        elif self.__func_type == FunctionType.FUNC_PURE_VARARG:
            self.__var_idx = item['var_idx']
        
        index = 0
        self.__parameter_types = []
        while True:
            pp = "p%d" % index
            if pp not in item:
                break
            t = item[pp]
            if t == 'in':
                self.__parameter_types.append(FunctionParameterType.P_IN)
            elif t == 'in_full':
                self.__parameter_types.append(FunctionParameterType.P_IN)
            elif t == 'out':
                self.__parameter_types.append(FunctionParameterType.P_OUT)
            elif t == 'void':
                self.__parameter_types.append(FunctionParameterType.P_VOID)
            elif t == 'in_arr':
                self.__parameter_types.append(FunctionParameterType.P_INARR)
            elif t == 'out_arr':
                self.__parameter_types.append(FunctionParameterType.P_OUTARR)
            else:
                raise RuntimeError("unknown parameter type : %s" % t)
            index += 1
        
        self.__return_type = FunctionReturnType.R_VOID
        if 'ret' in item:
            pp = item['ret']
            if pp == 'out':
                self.__return_type = FunctionReturnType.R_OUT
            elif pp == 'void':
                pass
            else:
                raise RuntimeError("unknown return type : %s" % pp)
        self.__initialized = True
    
    @property
    def name(self)->str:
        return self.__name
    
    @property
    def func_type(self)->FunctionType:
        return self.__func_type
    
    @property
    def count(self):
        """对于一个正常函数返回其参数格式
           对于一个带fmt string的变参函数，返回固定参数的个数
           对于一个纯变参函数，返回固定参数个数
        """
        if not self.__initialized:
            raise NotImplementedError()

        if self.__func_type == FunctionType.FUNC_NORMAL:
            return self.__count
        elif self.__func_type == FunctionType.FUNC_STR_VARARG:
            return self.__var_idx
        
        assert self.__count >= -1
        if self.__count == -1:
            """我们不关心,所以也不要为返回值为None的调用修正参数
            """
            return None
        return self.__count
    
    @property
    def var_index(self):
        if not self.__initialized:
            raise NotImplementedError()
        if self.__func_type == FunctionType.FUNC_NORMAL:
            return None
        return self.__var_idx
    
    @property
    def fstr_index(self):
        if not self.__initialized:
            raise NotImplementedError()
        if self.__func_type != FunctionType.FUNC_STR_VARARG:
            return None
        return self.__fstr_idx
    
    @property
    def parameter_types(self)->typing.List[FunctionParameterType]:
        if not self.__initialized:
            raise NotImplementedError()
        return self.__parameter_types
    
    @property
    def return_type(self)->FunctionReturnType:
        if not self.__initialized:
            raise NotImplementedError()
        return self.__return_type


def init_with_chunk_dict(items : dict)->typing.List[FunctionPrototype]:
    assert isinstance(items, dict)

    retv : typing.List[FunctionPrototype] = list()
    for name, entry in items.items():
        pp = FunctionPrototype(name, entry['type'])
        pp.initialize(entry)
        retv.append(pp)
    
    return retv


        