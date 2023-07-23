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
    log.info("Testing Vagrant")
    vm = Vagd(exe.path, vbox=Box.UBUNTU_FOCAL64, tmp=True, fast=True, ex=True)
    yield vm
    vm._v.halt()
    log.info("Testing Docker for Ubuntu")
    vm = Dogd(exe.path, image=Box.DOCKER_FOCAL, tmp=True, ex=True, fast=True)
    yield vm
    vm._client.containers.get(vm._id).kill()
    log.info("Testing Qemu")
    vm = Qegd(exe.path, img=Box.CLOUDIMAGE_FOCAL, tmp=True, ex=True, fast=True)
    yield vm
    log.info("Testing SSH")
    yield Shgd(exe.path, user=vm._user, port=vm._port, tmp=True, ex=True, fast=True)
    os.system('kill $(pgrep qemu)')
    yield wrapper.Empty()


for vm in vms():
    t = vm.start(argv=ARGS, env=ENV, gdbscript=GDB, api=API)

    sleep(1)
    g = wrapper.GDB(t)
    g.execute('p "PWN"')
    g.execute('c')

    log.info(t.recvall().decode())

print("Everything executed without errors")
