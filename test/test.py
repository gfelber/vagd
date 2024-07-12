#!/bin/env python3
import os

from pwn import *
import vagd.virts.pwngd
from vagd import Vagd, Qegd, Shgd, Dogd, Logd, wrapper, Box

GDB_OFF = 0x555555554000
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

LOCKFILE = vagd.virts.pwngd.Pwngd.LOCKFILE


def test_lockfile(expected):
    with open(LOCKFILE) as lockfile:
        assert lockfile.read() == expected, "bad lockfile"


def virts():
    log.info("Testing Local")
    yield Logd(exe.path)

    log.info("Testing Logging")
    context.log_level = 'error'
    yield Logd(exe.path)
    context.log_level = 'info'

    if args.VAGRANT:

        log.info("Testing Vagrant")

        if os.path.exists(Vagd.VAGRANTFILE_PATH):
            os.system(f"VAGRANT_CWD={Vagd.LOCAL_DIR} vagrant destroy -f")
            os.remove(Vagd.VAGRANTFILE_PATH)

        vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, packages=['cowsay'], tmp=True, fast=True, ex=True)
        assert vm.is_new, "vm should be new"
        assert vm._ssh.which('cowsay'), "cowsay wasn't installed"
        test_lockfile(Vagd.TYPE)
        yield vm
        vm._ssh.close()

        log.info("Testing Vagrant restore")
        vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, tmp=True, fast=True, ex=True)
        assert not vm.is_new, "vm shouldn't be new, restored"
        yield vm
        vm._ssh.close()

        log.info("Testing Vagrant restart")
        os.system(f"VAGRANT_CWD={Vagd.LOCAL_DIR} vagrant halt")
        vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, tmp=True, fast=True, ex=True)
        assert not vm.is_new, "vm shouldn't be new, restarted"
        yield vm
        vm._ssh.close()

        os.system("vagd clean")


    if not args.NODOGD:
      if os.path.exists(Dogd.LOCKFILE):
          os.remove(Dogd.LOCKFILE)
      log.info("Testing Docker for Ubuntu")
      vm = Dogd(exe.path + "_stat", image=Box.DOCKER_NOBLE, packages=['cowsay'], tmp=True, ex=True, fast=True)
      assert vm.is_new, "vm should be new"
      assert vm._ssh.which('cowsay'), "cowsay wasn't installed"
      yield vm
      vm._ssh.close()

      log.info("Testing Docker for Ubuntu restore")
      vm = Dogd(exe.path + "_stat", image=Box.DOCKER_NOBLE, tmp=True, ex=True, fast=True)
      assert not vm.is_new, "vm shouldn't be new, restored"
      yield vm
      vm._ssh.close()

      os.system("vagd clean")
      log.info("Testing Docker for Alpine")
      vm = Dogd(exe.path + "_stat", image=Box.DOCKER_ALPINE_316, tmp=True, ex=True, fast=True)
      assert vm.is_new, "vm should be new"
      yield vm
      vm._ssh.close()

      log.info("Testing Docker for Alpine restore")
      vm = Dogd(exe.path + "_stat", image=Box.DOCKER_ALPINE_316, tmp=True, ex=True, fast=True)
      assert not vm.is_new, "vm shouldn't be new, restored"
      yield vm
      vm._ssh.close()

      os.system("vagd clean")
    log.info("Testing Qemu")
    vm = Qegd(exe.path + "_stat", img=Box.QEMU_NOBLE, tmp=True, packages=['cowsay'], ex=True, fast=True)
    assert vm.is_new, "vm should be new"
    assert vm._ssh.which('cowsay'), "cowsay wasn't installed"
    yield vm
    vm._ssh.close()

    log.info("Testing Qemu restore")
    vm = Qegd(exe.path + "_stat", img=Box.QEMU_NOBLE, tmp=True, ex=True, fast=True)
    assert not vm.is_new, "vm shouldn't be new, restored"
    yield vm
    vm._ssh.close()
    user = vm._user
    port = vm._port

    log.info("Testing SSH")
    yield Shgd(exe.path + "_stat", user=user, port=port, keyfile=vm._ssh.keyfile, tmp=True, ex=True, fast=True)


for virt in virts():
    t = virt.start(argv=ARGS, env=ENV, gdbscript=GDB, api=API)

    sleep(1)
    if args.GDB:
        g = wrapper.GDB(t)
        g.execute('p "PWN"')
        g.execute('c')

    out = b'\n'.join(t.recvlines(3))

    log.info(out.decode())
    t.close()
    os.system('tmux kill-pane')

os.system("vagd clean")
sleep(1)
assert not os.path.exists(LOCKFILE), "lockfile shouldn't exist"

print("Everything executed without errors")
