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

- `vagd template [OPTIONS] [BINARY] [IP] [PORT]` to generate a template, list OPTIONS with help `-h`

```python
from pwn import *

GOFF   = 0x555555554000                               # GDB default base address
IP     = ''                                           # remote IP
PORT   = 0                                            # remote PORT
BINARY = ''                                           # PATH to local binary
ARGS   = []                                           # ARGS supplied to binary
ENV    = {}                                           # ENV supplied to binary

# GDB SCRIPT, executed at start of GDB session (e.g. set breakpoints here)
GDB    = f"""
set follow-fork-mode parent

c"""

context.binary = exe = ELF(BINARY, checksec=False)    # binary
context.aslr = args.ASLR                              # ASLR enabled (only GDB)

vm = None
# setup vagd vm
def setup():
  global vm
  if args.REMOTE or args.LOCAL:
    return

  try:
    # only load vagd if needed
    from vagd import Dogd, Qegd, Box
  except:
    log.error('Failed to import vagd, either run locally using LOCAL or install it')
  if not vm:
    vm = Dogd(BINARY, image=Box.DOCKER_UBUNTU, ex=True, fast=True)  # Docker
    # vm = Qegd(BINARY, img=Box.QEMU_UBUNTU, ex=True, fast=True)  # Qemu
  if vm.is_new:
    # additional setup here
    log.info('new vagd instance')


# get target (pwnlib.tubes.tube)
def get_target(**kw) -> tubes.tube:
  if args.REMOTE:
    # context.log_level = 'debug'
    return remote(IP, PORT)

  if args.LOCAL:
    if args.GDB:
      return gdb.debug([BINARY] + ARGS, env=ENV, gdbscript=GDB, **kw)
    return process([BINARY] + ARGS, env=ENV, **kw)

  return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, **kw)


setup()

#===========================================================
#                   EXPLOIT STARTS HERE
#===========================================================

# libc = ELF('', checksec=False)

t = get_target()

t.interactive() # or it()

```

- `vagd info BINARY` to print info about binary

```bash
# run as process in VM
./exploit.py
# run with gdb attached, requires tmux
./exploit.py GDB
# run with gdb and ASLR enabled
./exploit.py GDB ASLR
# run on remote IP:PORT
./exploit.py REMOTE
# run on a different remote target (IPv6 in brackets)
./exploit.py REMOTE HOST[:PORT] [PORT]
# run process locally
./exploit.py LOCAL [GDB]
```

I recommend using [pwndbg](https://github.com/pwndbg/pwndbg).

## Files

All created files ares stored in the local `./.vagd/` directory. Additional large files (e.g. cloudimages) are stored in the home directory `~/.share/local/vagd/` or handled by tools themselfs (e.g. Docker).

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

`IP` and `PORT` can also be given as `HOST:PORT` or `nc HOST PORT`, or through
the environment variables `VAGD_IP` and `VAGD_PORT`. `BINARY` may be omitted
(e.g. `vagd template host:1337`), the template then only sets `context.arch`.

`vagd template -a/--auto` detects the container image: it uses the final `FROM`
of a `Dockerfile` next to the binary (then in the current directory) and falls
back to the compiler string in the binary's `.comment` section (Ubuntu/Debian).

Resource limits of the target (like `ulimit` in a challenge's run script) can be set
with `Dogd(..., ulimit={"m": 8192, "d": 131072})` or per call `vm.start(ulimit=...)`.
Keys are `ulimit` options in sh units or `RLIMIT_*` names in bytes, values may be
`(soft, hard)` or `"unlimited"`.

To patch a binary explicitly, use `-p/--patchelf` with `-l/--libc`, repeatable
`-L/--library`, or `-i/--interpreter`. The original is saved as `<binary>.bak`;
the exact patched binary is used locally and inside the environment. Supplying
`-l/--libc` alone only includes libc in the generated template.

## [Documentation](https://vagd.gfelber.dev)

## Boxes

A listed of known working Boxes can be found in the [Documentation](http://vagd.gfelber.dev/autoapi/vagd/box/index.html#module-vagd.box).
Other images might also work but currently only distributions that use `apt` and alpine for Docker are supported.
This limitation may be circumvented by creating a target yourself (with the dependencies gdbserver, python, openssh) and creating a ssh connection via Shgd.

## Troubleshooting

### background processes

all instances continue to run in the background (after a vagd object has been started), this improves the runtime greatly after the first execution of the exploit. But this means that instances must be killed manually e.g.: `vagd clean`

### gdb & gdbserver

For containers (`Dogd`, `Pogd`) the host gdb attaches directly to the process (`native=True`, default) and
uses the container root as sysroot, no gdbserver or sshfs is involved. This requires that the container
user has the same uid as the host user (the generated Dockerfile takes care of this) and `kernel.yama.ptrace_scope <= 1`.
Otherwise, and for VMs, gdbserver is used; I recommend using [pwndbg](https://github.com/pwndbg/pwndbg).
Other well known gdb plugins like [peda](https://github.com/longld/peda) aren't compatible with gdbserver and therefore won't work.

### files

files on the virtual instance are never overwritten this has performance reason (so files aren't always copied if the exploit is run). If you need to updated files on the remote either use `vagd scp` or create use temporary directories `Dogd(..., tmp=True)`

### gdb performance

Using gdbserver and gdb to index libraries can be very slow. Therefore an experimental feature is available that mounts libraries locally: `Dogd(..., ex=True, fast=True)`

## Future plans

### Better Docker integration

- migrate away from ssh (attach from host) to get lower latency
- additionally virtualize containers (Qemu) in order to change the used kernel
