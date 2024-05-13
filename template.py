#!/bin/python
from vagd import Vagd, Qegd, wrapper, box
from pwn import *

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = ''
ARGS = []
ENV = {}
GDB = f"""

c"""

context.binary = exe = ELF(BINARY, checksec=False)
context.aslr = False

byt = lambda x: str(x).encode()


def get_target(**kw):
    if args.REMOTE:
        context.log_level = 'debug'
        return remote(IP, PORT)

    vm = Vagd(exe.path, vbox=box.UBUNTU_FOCAL64, ex=True, fast=True)
    # vm = Qegd(exe.path, img=box.CLOUDIMAGE_FOCAL, user='ubuntu', ex=True, fast=True)
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, **kw)


t = get_target()

t.interactive()
