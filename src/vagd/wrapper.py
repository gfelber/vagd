from . import gdb


class Empty:
    def __getattr__(self, name):
        """
        create empty function wrapper
        :param name: name of attribute
        :return: None
        """
        return lambda *args, **kwargs: None


class GDB:
    def __new__(cls, target):
        # type:() -> gdb.GDB
        # Weird type hint that allows type hinting from stub files
        # stubs from: https://github.com/python/typeshed/tree/main/stubs/gdb/gdb
        # include subdir from other remote: https://stackoverflow.com/a/30386041
        """
        returns GDB out of target if it has attribute gdb
        :param target: target to check for wrapper
        :return: returns Empty wrapper or
        """
        if hasattr(target, 'gdb'):
            return target.gdb
        else:
            return Empty()
