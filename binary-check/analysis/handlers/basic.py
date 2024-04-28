import enum


class AuthType(enum.IntEnum):
    AUTH_ENABLE = 0,
    AUTH_DISABLE = 1,
    AUTH_UNKNOWN = 2


class HandlerItem(object):
    def __init__(self):
        self.auth = AuthType.AUTH_UNKNOWN
        self.address = -1
        self.mimeType = None
        self.pattern = None
        self.symbol = None

    @staticmethod
    def make(auth, address):
        assert isinstance(auth, AuthType)
        item = HandlerItem()
        item.auth = auth
        item.address = address
        return item
