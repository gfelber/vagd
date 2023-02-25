#!/bin/python
from vagd import Vagd, gdb_wrapper
from pwn import *

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = ''
ARGS = ()
ENV = {}
ASLR = False
API = False
BOX = Vagd.VAGRANT_BOX
GDB = f"""
c
"""
context.binary = exe = ELF(BINARY, checksec=False)

byt = lambda x: str(x).encode()


def get_target():
    if args.REMOTE:
        context.log_level = 'debug'
        return remote(IP, PORT)

    vm = Vagd(exe.path, box=BOX)
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, aslr=ASLR, api=API)


t = get_target()
g = t.gdb if hasattr(t, 'gdb') else gdb_wrapper.GDBWrapper()
g.execute('p "PWN"')

t.interactive()
