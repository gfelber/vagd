#!/bin/env python3
import os

from pwn import *
import vagd.virts.pwngd
from vagd import Vagd, Qegd, Shgd, Dogd, Logd, wrapper, Box

GDB_OFF = 0x555555554000
IP = ""
PORT = 0
BINARY = "./bin/sysinfo_stat"
ARGS = []
ENV = {}
API = True
GDB = """
b main
c"""

context.binary = exe = ELF(BINARY, checksec=False)
context.aslr = False

byt = lambda x: str(x).encode()

LOCKFILE = vagd.virts.pwngd.Pwngd.LOCKFILE


def test_lockfile(expected):
  with open(LOCKFILE) as lockfile:
    assert lockfile.read() == expected, "bad lockfile"


def stage(msg, *args):
  log.info("======== " + msg + " ========", *args)


def virts():
  stage("Testing Local")
  yield Logd(exe.path)

  stage("Testing Logging")
  context.log_level = "error"
  yield Logd(exe.path)
  context.log_level = "info"

  if args.VAGRANT:
    stage("Testing Vagrant")

    if os.path.exists(Vagd.VAGRANTFILE_PATH):
      os.system(f"VAGRANT_CWD={Vagd.LOCAL_DIR} vagrant destroy -f")
      os.remove(Vagd.VAGRANTFILE_PATH)

    vm = Vagd(
      exe.path,
      vbox=Box.VAGRANT_JAMMY64,
      packages=["cowsay"],
      tmp=True,
      fast=True,
      ex=True,
    )
    assert vm.is_new, "vm should be new"
    assert vm._ssh.which("cowsay"), "cowsay wasn't installed"
    test_lockfile(Vagd.TYPE)
    yield vm
    vm._ssh.close()

    stage("Testing Vagrant restore")
    vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, tmp=True, fast=True, ex=True)
    assert not vm.is_new, "vm shouldn't be new, restored"
    yield vm
    vm._ssh.close()

    stage("Testing Vagrant restart")
    os.system(f"VAGRANT_CWD={Vagd.LOCAL_DIR} vagrant halt")
    vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, tmp=True, fast=True, ex=True)
    assert not vm.is_new, "vm shouldn't be new, restarted"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")

  if not args.NODOGD:
    if os.path.exists(Dogd.LOCKFILE):
      os.remove(Dogd.LOCKFILE)
    stage("Testing Docker for Ubuntu")
    vm = Dogd(
      exe.path,
      image=Box.DOCKER_UBUNTU,
      packages=["cowsay"],
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    assert vm._ssh.which("cowsay"), "cowsay wasn't installed"
    yield vm
    vm._ssh.close()

    stage("Testing Docker for Ubuntu restore")
    vm = Dogd(exe.path, image=Box.DOCKER_UBUNTU, tmp=True, ex=True, fast=True)
    assert not vm.is_new, "vm shouldn't be new, restored"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")
    sleep(1)
    stage("Testing Docker for Ubuntu (root)")
    vm = Dogd(
      exe.path,
      user="root",
      image=Box.DOCKER_UBUNTU,
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")
    sleep(1)
    stage("Testing Docker for Alpine")
    vm = Dogd(
      exe.path,
      image=Box.DOCKER_ALPINE,
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    yield vm
    vm._ssh.close()

    stage("Testing Docker for Alpine restore")
    vm = Dogd(
      exe.path,
      image=Box.DOCKER_ALPINE,
      tmp=True,
      ex=True,
      fast=True,
    )
    assert not vm.is_new, "vm shouldn't be new, restored"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")
    sleep(1)
    stage("Testing Docker for Alpine (root)")
    vm = Dogd(
      exe.path,
      image=Box.DOCKER_ALPINE,
      user='root',
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")

  stage("Testing Qemu")
  vm = Qegd(
    exe.path,
    img=Box.QEMU_UBUNTU,
    tmp=True,
    packages=["cowsay"],
    ex=True,
    fast=True,
  )
  assert vm.is_new, "vm should be new"
  assert vm._ssh.which("cowsay"), "cowsay wasn't installed"
  yield vm
  vm._ssh.close()

  stage("Testing Qemu restore")
  vm = Qegd(exe.path, img=Box.QEMU_UBUNTU, tmp=True, ex=True, fast=True)
  assert not vm.is_new, "vm shouldn't be new, restored"
  yield vm
  vm._ssh.close()

  os.system("vagd clean")
  sleep(1)
  stage("Testing Qemu (root)")
  vm = Qegd(
    exe.path,
    img=Box.QEMU_UBUNTU,
    user="root",
    tmp=True,
    ex=True,
    fast=True,
    root=True,
  )
  assert vm.is_new, "vm should be new"
  yield vm
  vm._ssh.close()
  user = vm._user
  port = vm._port

  stage("Testing SSH")
  yield Shgd(
    exe.path,
    user=user,
    port=port,
    keyfile=vm._ssh.keyfile,
    tmp=True,
    ex=True,
    fast=True,
  )


for virt in virts():
  t = virt.start(argv=ARGS, env=ENV, gdbscript=GDB, api=API)

  sleep(1)
  if args.GDB:
    g = wrapper.GDB(t)
    g.execute('p "PWN"')
    g.execute("c")

  out = b"\n".join(t.recvlines(3))

  log.info(out.decode())
  t.close()
  os.system("tmux kill-pane")

os.system("vagd clean")
sleep(1)
assert not os.path.exists(LOCKFILE), "lockfile shouldn't exist"

stage("Everything executed without errors")
