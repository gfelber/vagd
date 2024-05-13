#!/bin/python
from pwn import *

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = ''
ARGS = ('', )
ENV = {'ENV_NAME':'VALUE'}
ASLR = False
GDB = f"""

c
"""
context.binary = exe = ELF(BINARY, checksec=False)

byt = lambda x: str(x).encode() 
def get_target():
    if args.PLT_DEBUG:
        return gdb.debug((exe.path,) + ARGS, GDB, env=ENV, aslr=ASLR)

    context.log_level = 'debug'

    if args.LOCAL:
        return process((exe.path,) + ARGS, env=ENV, aslr=ASLR)

    return remote(IP, PORT)

t = get_target()
