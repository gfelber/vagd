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

## Recommendations

Consider adding these aliases to either `~./.bash_aliases`, `~./.bashrc` or other

```bash
alias vagd='python -m vagd'
# example use to ssh to guest
# vagdssh
alias vagdssh='VAGRANT_CWD=.vagd vagrant ssh'
# example use to copy flag.txt from host to guest (only works if Port is 2222)
# vagdscp ./flag.txt ./
vagdscp() {
  scp -P 2222 -o StrictHostKeyChecking=no -i ./vagd/.vagrant/machines/default/virtualbox/private_key ${@:3} $1 vagrant@localhost:$2
}
# example use to ssh to guest
# dogdssh
alias dogdssh='ssh -o "StrictHostKeyChecking=no" -i ~/.vagd/keyfile -p $(cut -d":" -f 2 .vagd/docker.lock) vagd@0.0.0.0'
# example use to copy flag.txt from host to guest
# dogdscp ./flag.txt
dogdscp() {
  scp -P $(cut -d":" -f 2 .vagd/docker.lock) -o StrictHostKeyChecking=no -i ~/.vagd/keyfile ${@:3} $1 vagd@localhost:$2
}
# example use to spawn shell in guest 
# dogdexec sh
alias dogdexec='docker exec -it $(cut ./.vagd/docker.lock -d":" -f 1)'
# example use to copy /etc/passwd from guest to host
# dogdcp /etc/passwd ./
dogdcp() {
  docker cp "$(cut ./.vagd/docker.lock -d":" -f 1):$1" $2
}
# example use to ssh to guest
# qegdssh
alias qegdssh='ssh -o "StrictHostKeyChecking=no" -i ~/.vagd/keyfile -p $(cat .vagd/qemu.lock) ubuntu@0.0.0.0'
# example use to copy flag.txt from host to guest
# qegdscp ./flag.txt
qegdscp() {
  scp -P $(cat .vagd/qemu.lock) -o StrictHostKeyChecking=no -i ~/.vagd/keyfile ${@:3} $1 ubuntu@localhost:$2
}
```



## [Documentation](https://gfelber.github.io/vagd/index.html)



## Boxes

A listed of known working Boxes can be found in the [Documentation](https://gfelber.github.io/vagd/vagd.html#module-vagd.box).
Other images might also work but currently only distributions that use `apt` and alpine for Docker are supported.
This limitation may be circumvented by create a container yourself (with the dependencies gdbserver, python, openssh) and creating a ssh connection via Shgd.



## Future plans

### pre configured Vagrant boxes / QEMU Images / Docker Image

created pre configured environments with preinstalled lib debug symbols and gdbserver to lower init runtime.

### Better Docker integration

created a Docker integration that allows loading existing Dockerfiles (maybe docker-compose), also add a feature that additionally virtualizes (Vagrant/Qemu) them to change the used kernel.
