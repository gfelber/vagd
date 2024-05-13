#!/bin/python
from vagd import Vagd, Qegd, wrapper
from vagd.box import Box
from pwn import *

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = './bin/sysinfo'
ARGS = []
ENV = {}
API = True
BOX = Box.UBUNTU_FOCAL64
GDB = f"""
b main
c"""

context.binary = exe = ELF(BINARY, checksec=False)
context.aslr = False

byt = lambda x: str(x).encode()


def get_target(**kw):
    if args.REMOTE:
        context.log_level = 'debug'
        return remote(IP, PORT)

    # vm = Vagd(exe.path, vbox=BOX, tmp=True, fast=True, ex=True)
    vm = Qegd(exe.path, img=Box.CLOUDIMAGE_FOCAL, tmp=True, ex=True, fast=True)
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, api=API, **kw)


t = get_target()
g = wrapper.GDB(t)
g.execute('p "PWN"')

t.interactive()
