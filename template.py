#!/bin/python
from vagd import Vagd, wrapper, box
from pwn import *

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = ''
ARGS = ()
ENV = {}
API = False
BOX = box.UBUNTU_FOCAL64
GDB = f"""

c"""
context.binary = exe = ELF(BINARY, checksec=False)
context.aslr = False

byt = lambda x: str(x).encode()


def get_target(*a, **kwargs):
    if args.REMOTE:
        context.log_level = 'debug'
        return remote(IP, PORT)

    vm = Vagd(exe.path, vbox=BOX)
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, ex=False, *a, **kwargs)


t = get_target()
g = t.gdb if hasattr(t, 'gdb') else wrapper.Empty()
g.execute('p "PWN"')

t.interactive()
