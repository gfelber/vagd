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

use `python -m vagd` to generate a template

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



## [Documentation](https://gfelber.github.io/vagd/index.html)



## Boxes

the following boxes were tested and work, box constants are inside `vagd.box.Box`

* Vagrant
  * UBUNTU_JAMMY64 = 'ubuntu/jammy64'
  * UBUNTU_FOCAL64 = 'ubuntu/focal64'
  * UBUNTU_BIONIC64 = 'ubuntu/bionic64'
  * UBUNTU_XENIAL64 = 'ubuntu/xenial64'
* QEMU (cached in `~/.vagd/qemu-imgs`)
  * [CLOUDIMAGE_JAMMY](https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img)
  * [CLOUDIMAGE_FOCAL](https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img)
  * [CLOUDIMAGE_BIONIC](https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img)
  * [CLOUDIMAGE_XENIAL](https://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-disk1.img)
* Docker
  * DOCKER_JAMMY = 'ubuntu:jammy'
  * DOCKER_FOCAL = 'ubuntu:focal'
  * DOCKER_BIONIC = 'ubuntu:bionic'
  * DOCKER_XENIAL = 'ubuntu:xenial'


currently only distributions that use `apt` are supported



## Future plans

### pre configured Vagrant boxes / QEMU Images / Docker Image

created pre configured environments with preinstalled lib debug symbols and gdbserver to lower init runtime.

### Better Docker integration

created a Docker integration that allows loading existing Dockerfiles (maybe docker-compose), also add a feature that additionally virtualizes (Vagrant/Qemu) them to change the used kernel.
