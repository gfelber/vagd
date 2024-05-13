#!/bin/python
from pwn import *
from vagd import Vagd

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = ''
ARGS = ('',)
ENV = {'ENV_NAME': 'VALUE'}
ASLR = False
GDB = f"""

c
"""
context.binary = exe = ELF(BINARY, checksec=False)

byt = lambda x: str(x).encode()


def get_target():
    if args.REMOTE:
        context.log_level = 'debug'
        return remote(IP, PORT)

    vagd = Vagd(exe.path)
    return vagd.start(argv=ARGS, env=ENV, aslr=ASLR)



t = get_target()
t.interactive()
