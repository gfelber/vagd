#!/bin/env python3
import os
import shutil
import subprocess
import tempfile

from pwn import *
from typer.testing import CliRunner
import vagd.virts.pwngd
from vagd import Vagd, Qegd, Shgd, Dogd, Pogd, Logd, wrapper, Box
from vagd.cli import app
from vagd.patch import patch_binary
from vagd.detect import detect_image

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
GDB_ARGS = ["-ex", "set debuginfod enabled off"]

context.binary = exe = ELF(BINARY, checksec=False)
context.aslr = False

byt = lambda x: str(x).encode()

LOCKFILE = vagd.virts.pwngd.Pwngd.LOCKFILE


def test_lockfile(expected):
  with open(LOCKFILE) as lockfile:
    assert lockfile.read() == expected, "bad lockfile"


def stage(msg, *args):
  log.info("======== " + msg + " ========", *args)


def test_patchelf():
  """Supplied artifacts take priority without disabling system fallbacks."""
  source_binary = "/bin/echo"
  interpreter = subprocess.check_output(
    ["patchelf", "--print-interpreter", source_binary], text=True
  ).strip()

  with tempfile.TemporaryDirectory(dir="./bin") as directory:
    binary = os.path.abspath(os.path.join(directory, "echo"))
    shutil.copy2(source_binary, binary)
    subprocess.run(["patchelf", "--set-rpath", "/existing", binary], check=True)
    with open(binary, "rb") as executable:
      original = executable.read()

    libraries, staged_interpreter = patch_binary(
      binary, libraries=[interpreter], interpreter=interpreter
    )

    with open(binary + ".bak", "rb") as backup:
      assert backup.read() == original, "bad binary backup"
    assert os.access(libraries[0], os.R_OK | os.X_OK), "bad library permissions"
    assert os.access(staged_interpreter, os.R_OK | os.X_OK), "bad interpreter permissions"
    rpath = subprocess.check_output(["patchelf", "--print-rpath", binary], text=True)
    assert rpath.strip() == "$ORIGIN:/existing"
    assert (
      subprocess.check_output(["patchelf", "--print-interpreter", binary], text=True).strip()
      == "./" + os.path.basename(staged_interpreter)
    )
    output = subprocess.check_output(["./echo", "patched"], cwd=directory)
    assert output == b"patched\n", "patched binary failed"


def test_patchelf_cli():
  """Patching requires -p; -l alone retains its original behavior."""
  source_binary = "/bin/echo"
  interpreter = subprocess.check_output(
    ["patchelf", "--print-interpreter", source_binary], text=True
  ).strip()

  with tempfile.TemporaryDirectory(dir="./bin") as directory:
    binary = os.path.abspath(os.path.join(directory, "echo"))
    output = os.path.join(directory, "exploit.py")
    shutil.copy2(source_binary, binary)
    with open(binary, "rb") as executable:
      original = executable.read()

    runner = CliRunner()
    result = runner.invoke(
      app, ["template", binary, "--local", "--no-info", "-o", output, "-l", interpreter]
    )
    assert result.exit_code == 0, result.output
    with open(binary, "rb") as executable:
      assert executable.read() == original, "-l unexpectedly patched the binary"
    assert not os.path.exists(binary + ".bak"), "-l unexpectedly created a backup"

    result = runner.invoke(
      app,
      [
        "template",
        binary,
        "--local",
        "--no-info",
        "-o",
        output,
        "-p",
        "-l",
        interpreter,
        "-i",
        interpreter,
      ],
    )
    assert result.exit_code == 0, result.output
    assert os.path.exists(binary + ".bak"), "-p did not create a backup"


def test_auto_image():
  """-a prefers a Dockerfile next to the binary and falls back to .comment."""
  dockerfile = """ARG UBUNTU=22.04
FROM --platform=linux/amd64 ubuntu:${UBUNTU} AS builder
RUN apt update && \\
    apt install -y gcc
FROM builder
"""
  with tempfile.TemporaryDirectory(dir="./bin") as directory:
    binary = os.path.join(directory, "echo")
    shutil.copy2("/bin/echo", binary)
    comment = os.path.join(directory, "comment")
    with open(comment, "wb") as comment_file:
      comment_file.write(b"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\0")
    subprocess.run(["objcopy", "--remove-section", ".comment", binary], check=False)
    subprocess.run(["objcopy", "--add-section", f".comment={comment}", binary], check=True)
    assert detect_image(binary) == ("ubuntu:22.04", ".comment"), "bad .comment detection"

    with open(os.path.join(directory, "Dockerfile"), "w") as dockerfile_file:
      dockerfile_file.write(dockerfile)
    image, source = detect_image(binary)
    assert image == "ubuntu:22.04", "bad Dockerfile detection"
    assert source.endswith("Dockerfile"), "Dockerfile should take priority"

    runner = CliRunner()
    result = runner.invoke(app, ["template", binary, "-a", "--no-info"])
    assert result.exit_code == 0, result.output
    assert "BOX    = 'ubuntu:22.04'" in result.output, "template missing detected image"
    result = runner.invoke(app, ["template", binary, "-a", "--image", "ubuntu:focal"])
    assert result.exit_code == 1, "-a and --image should conflict"
    result = runner.invoke(app, ["template", "/bin/true", "-a", "--no-info"])
    assert result.exit_code == 1, "detection should fail without Dockerfile or known .comment"


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
    stage("Testing Docker for Arch")
    vm = Dogd(
      exe.path,
      image=Box.DOCKER_ARCH,
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    yield vm
    vm._ssh.close()

    stage("Testing Docker for Arch restore")
    vm = Dogd(
      exe.path,
      image=Box.DOCKER_ARCH,
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
      user="root",
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
      user="root",
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")

  if args.PODMAN:
    if os.path.exists(Pogd.LOCKFILE):
      os.remove(Pogd.LOCKFILE)
    stage("Testing Podman for Ubuntu")
    vm = Pogd(
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

    stage("Testing Podman for Ubuntu restore")
    vm = Pogd(exe.path, image=Box.DOCKER_UBUNTU, tmp=True, ex=True, fast=True)
    assert not vm.is_new, "vm shouldn't be new, restored"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")
    sleep(1)
    stage("Testing Podman for Arch")
    vm = Pogd(
      exe.path,
      image=Box.DOCKER_ARCH,
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    yield vm
    vm._ssh.close()

    stage("Testing Podman for Arch restore")
    vm = Pogd(
      exe.path,
      image=Box.DOCKER_ARCH,
      tmp=True,
      ex=True,
      fast=True,
    )
    assert not vm.is_new, "vm shouldn't be new, restored"
    yield vm
    vm._ssh.close()

    os.system("vagd clean")
    sleep(1)
    stage("Testing Podman for Alpine")
    vm = Pogd(
      exe.path,
      image=Box.DOCKER_ALPINE,
      tmp=True,
      ex=True,
      fast=True,
    )
    assert vm.is_new, "vm should be new"
    yield vm
    vm._ssh.close()

    stage("Testing Podman for Alpine restore")
    vm = Pogd(
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

  if not args.NO_QEMU:
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


stage("Testing patchelf library support")
test_patchelf()
test_patchelf_cli()
stage("Testing image detection")
test_auto_image()

for virt in virts():
  if not isinstance(virt, Logd):
    socket_t = virt.process(argv=ARGS, env=ENV, socket=True)
    socket_t.shutdown("send")
    socket_out = b"\n".join(socket_t.recvlines(3))
    assert b"Kernel name:" in socket_out, "socket transport returned bad output"
    socket_t.close()

  start_kwargs = {"socket": True} if not isinstance(virt, Logd) else {}
  t = virt.start(
    argv=ARGS,
    env=ENV,
    gdbscript=GDB,
    gdb_args=GDB_ARGS,
    api=API,
    **start_kwargs,
  )

  sleep(1)
  if args.GDB:
    g = wrapper.GDB(t)
    g.execute('p "PWN"')
    g.execute("c")

  out = b"\n".join(t.recvlines(3))
  assert b"Kernel name:" in out, "target returned bad output"

  log.info(out.decode())
  if args.GDB:
    try:
      g.execute("set confirm off")
      g.execute("quit")
    except EOFError:
      pass
  t.close()

os.system("vagd clean")
sleep(1)
assert not os.path.exists(LOCKFILE), "lockfile shouldn't exist"

stage("Everything executed without errors")
