#!/bin/python
import os
import time

from vagd import Vagd, Qegd, Shgd, Dogd, wrapper, Box
from pwn import *

GDB_OFF = 0x555555555000
IP = ''
PORT = 0
BINARY = './bin/sysinfo'
ARGS = []
ENV = {}
API = True
GDB = f"""
b main
c"""

context.binary = exe = ELF(BINARY, checksec=False)
context.aslr = False

byt = lambda x: str(x).encode()


def vms():
    vm = Vagd(exe.path, vbox=Box.UBUNTU_FOCAL64, tmp=True, fast=True, ex=True)
    yield vm
    vm._v.halt()
    vm = Dogd(exe.path, user='ubuntu', image=Box.DOCKER_FOCAL, tmp=True, ex=True, fast=True)
    yield vm
    vm._client.containers.get(vm._id).kill()
    vm = Qegd(exe.path, user='ubuntu', img=Box.CLOUDIMAGE_FOCAL, tmp=True, ex=True, fast=True)
    yield vm
    yield Shgd(exe.path, user=vm._user, port=vm._port, tmp=True, ex=True, fast=True)
    os.system('kill $(pgrep qemu)')
    yield wrapper.Empty()


for vm in vms():
    t = vm.start(argv=ARGS, env=ENV, gdbscript=GDB, api=API)

    g = wrapper.GDB(t)
    g.execute('p "PWN"')
    g.execute('c')

    t.recvall()

print("Everything executed without errors")
