from . import gdb


class Empty:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


class GDB:
    def __new__(cls, target):
        # type:() -> gdb.GDB
        if hasattr(target, 'gdb'):
            return target.gdb
        else:
            return Empty()
