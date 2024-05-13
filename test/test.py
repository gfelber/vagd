#!/bin/python
from pwn import *
from vagd import Vagd

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = './sysinfo'
ARGS = ('',)
ENV = {'ENV_NAME': 'VALUE'}
ASLR = False
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
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, aslr=ASLR)



t = get_target()
t.interactive()
