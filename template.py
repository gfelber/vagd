#!/bin/python
from vagd import Vagd, Qegd, Dogd, Box
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


vm = None
def get_target(**kw):
    global vm
    if args.REMOTE:
        context.log_level = 'debug'
        return remote(IP, PORT)

    if not vm:
        vm = Vagd(exe.path, vbox=Box.UBUNTU_FOCAL64, ex=True, fast=True)
        # vm = Qegd(exe.path, img=Box.CLOUDIMAGE_FOCAL, user='ubuntu', ex=True, fast=True)
        # vm = Dogd(exe.path, img=Box.DOCKER_FOCAL, ex=True, fast=True)
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, **kw)


t = get_target()

t.interactive()
