import enum
import typing

class SocketParamType(enum.IntEnum):
    SOCKET_FD = 0,
    SOCKET_LEN = 1,
    SOCKET_BUFFER = 2

class SocketPrototype(object):
    def __init__(self, item : dict, name : str):
        self.__params : typing.List[SocketParamType] = list()
        self.__name : str = name
        size = item["size"]
        for i in range(size):
            key = "p%d" % (i)
            value = item[key]
            if value == "fd":
                self.__params.append(SocketParamType.SOCKET_FD)
            elif value == "len":
                self.__params.append(SocketParamType.SOCKET_LEN)
            elif value == "buffer":
                self.__params.append(SocketParamType.SOCKET_BUFFER)
            else:
                raise RuntimeError("unknown type : %s" % value)
    @property
    def params(self)->typing.List[SocketParamType]:
        return self.__params
    
    @property
    def name(self)->str:
        return self.__name



