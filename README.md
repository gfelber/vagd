[![PyPI](https://img.shields.io/pypi/v/vagd?style=flat)](https://pypi.org/project/vagd/) [![docs](https://img.shields.io/badge/docs-passing-success)](https://vagd.gfelber.dev)

# VAGD

VirtuAlization GDb integrations in pwntools

## Installation

```bash
pip install vagd
```
or from repo with
```bash
git clone https://github.com/gfelber/vagd
pip install ./vagd/
```

## Usage

+ `vagd template [OPTIONS] [BINARY] [IP] [PORT]` to generate a template, list OPTIONS with help `-h`

```python
#!/usr/bin/env python
from pwn import *
from vagd import Dogd, Qegd, Vagd, Shgd

IP = ''         # remote IP
PORT = 0        # remote PORT
BINARY = ''     # PATH to local binary e.g. ./chal
ARGS = []       # ARGS supplied to binary 
ENV = {}        # ENVs supplied to binary
# GDB SCRIPT, executed at start of GDB session (set breakpoint here)
GDB = f"""

c"""

context.binary = exe = ELF(BINARY, checksec=False)
# enable disable ASLR (works for GDB)
context.aslr = False

vm = None
def get_target(**kw):
    global vm

    if args.REMOTE:
        context.log_level = 'debug'
        return remote(IP, PORT)

    if not vm:
        # Docker 
        vm = Dogd(exe.path, image="ubuntu:jammy", ex=True, fast=True)
        # or Qemu
        vm = Qegd(exe.path, img="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img", ex=True, fast=True)
        # or Vagrant
        vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, ex=True, fast=True)
        # or SSH
        vm = Shgd(exe.path, user='user', host='localhost', port=22, ex=True, fast=True)
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, **kw) # returns a pwn.process (similar to pwn.process())


t = get_target()

t.interactive()


```

+ `vagd info BINARY` to print info about binary

```bash
# run as process in VM
./exploit.py
# run as gdb server in VM requires tmux
./exploit.py GDB
# run on remote IP:PORT
./exploit.py REMOTE
```

I recommend using [pwndbg](https://github.com/pwndbg/pwndbg).

## Files

All created files ares stored in the local `./.vagd/` directory. Additional large files (e.g. cloudimages) are stored in the home directory `~/.vagd/` or handled by tools themselfs (e.g. Vagrant, Docker).

## CLI

```bash
alias vagd="python -m vagd" # or install with pip / pipx
# help message
vagd -h
# analyses the binary, prints checksec and .comment (often includes Distro and Compiler info)
vagd info BINARY
# creates template, for more info use: vagd template -h
vagd template [OPTIONS] [BINARY] [IP] [PORT]
# ssh to current vagd instance, for more info use: vagd ssh -h
vagd ssh [OPTIONS]
# scp file to/from vagd instance, for more info use: vagd scp -h
# e.g. vagd scp ./test_file vagd:./ # vagd:./ is default target
vagd scp [OPTIONS] SOURCE [TARGET]
# stop and remove current vagd instance, for more info use: vagd clean -h
vagd clean [OPTIONS]
```

## [Documentation](https://vagd.gfelber.dev)



## Boxes

A listed of known working Boxes can be found in the [Documentation](http://vagd.gfelber.dev/autoapi/vagd/box/index.html#module-vagd.box).
Other images might also work but currently only distributions that use `apt` and alpine for Docker are supported.
This limitation may be circumvented by creating a target yourself (with the dependencies gdbserver, python, openssh) and creating a ssh connection via Shgd.



## Future plans

### pre configured Vagrant boxes / QEMU Images / Docker Image

created pre configured environments with preinstalled lib debug symbols and gdbserver to lower init runtime.

### Better Docker integration

created a Docker integration that allows loading existing Dockerfiles (maybe docker-compose), also add a feature that additionally virtualizes (Vagrant/Qemu) them to change the used kernel.
