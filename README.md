[![PyPI](https://img.shields.io/pypi/v/vagd?style=flat)](https://pypi.org/project/vagd/) [![docs](https://img.shields.io/badge/docs-passing-success)](https://gfelber.github.io/vagd/index.html)

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

## [Documentation](https://gfelber.github.io/vagd/index.html)



## Boxes

A listed of known working Boxes can be found in the [Documentation](https://gfelber.github.io/vagd/autoapi/vagd/box/index.html#module-vagd.box).
Other images might also work but currently only distributions that use `apt` and alpine for Docker are supported.
This limitation may be circumvented by creating a target yourself (with the dependencies gdbserver, python, openssh) and creating a ssh connection via Shgd.



## Future plans

### pre configured Vagrant boxes / QEMU Images / Docker Image

created pre configured environments with preinstalled lib debug symbols and gdbserver to lower init runtime.

### Better Docker integration

created a Docker integration that allows loading existing Dockerfiles (maybe docker-compose), also add a feature that additionally virtualizes (Vagrant/Qemu) them to change the used kernel.
