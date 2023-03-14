[![PyPI](https://img.shields.io/pypi/v/vagd?style=flat)](https://pypi.org/project/vagd/)[![docs](https://img.shields.io/badge/docs-passing-success)](https://gfelber.github.io/vagd/index.html)

# VAGD

VirtuAlization GDb integrations in pwntools

## Installation

```bash
pip install vagd pwntools
```
or
 ```bash
 pip install .
 pip install -r requirements.txt
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

## Features

**vagd.Vagd**

Child of `vagd.pwngd.Pwngd` setups a vagrant vm

SSH from cmd:

```bash
VAGRANT_CWD=.vagd vagrant ssh
```

halt from cmd

```bash
VAGRANT_CWD=.vagd vagrant halt
```

destroy from cmd

```bash
VAGRANT_CWD=.vagd vagrant destroy
```



| required | name        | type | descripton                                                |
| -------- | ----------- | ---- | --------------------------------------------------------- |
| X        | binary      | str  | binary to debug on  vagrant vm                            |
|          | Vagrantfile | str  | Location of Vagrantfile (default current .vagd directory) |
|          | vbox        | str  | vagrant box to use (Default: ubuntu/focal64)              |
|          | **kwargs    | Any  | Parameters to pass through to super constructor           |

**vagd.Qegd**

Child of `vagd.pwngd.Pwngd` setups a qemu machine

Images are cached in `~/.vagd/qemu-imgs/`

SSH from cmd:

````bash
ssh -o "StrictHostKeyChecking=no" -i .vagd/keyfile -p $(cat .vagd/qemu.lock) ubuntu@0.0.0.0
````

Kill from cmd:

```bash
kill $(pgrep qemu)
```



| required | name     | type | descripton                                                   |
| -------- | -------- | ---- | ------------------------------------------------------------ |
| X        | binary   | str  | binary to debug on  vagrant vm                               |
|          | img      | str  | Location of qemu cloudimage local or remote (URL) (Default: [Cloudimage-Ubuntu-Focal](https://cloud-images.ubuntu.com/focal/current/)) |
|          | user     | str  | Default user (depended on image) (Default: ubuntu)           |
|          | **kwargs | Any  | Parameters to pass through to super constructor              |

**vagd.pwngd.Pwngd**

Abstract Class for Vagd, setups vm. Requires a valid ssh connection: hostname, port, user and keyfile (not password)

Parameters:

| required | experimental | name     | type         | description                                                  |
| -------- | ------------ | -------- | ------------ | ------------------------------------------------------------ |
| X        |              | binary   | str          | binary to debug on  vagrant vm                               |
|          |              | files    | str \| tuple | other files to upload to vm, all files are uploaded to current working directory (home or tmp) |
|          |              | packages | Iterable     | Other packages to install on remote system                   |
|          |              | tmp      | bool         | if the created directory in the vm should be temporary, requires new upload after each execution |
|          | X            | fast     | bool         | fast debug, mounts library files locally with **sshfs** in newly created directory ./.vagd/sysroot/lib/ for faster symbol reading |
|          | x            | ex       | bool         | enables experimental features for the whole object           |



**vagd.pwngd.Pwngb.put**	

upload file or directory to vm

Parameters:

| required | name   | type | description                                                  |
| -------- | ------ | ---- | ------------------------------------------------------------ |
| x        | file   | str  | path of file to upload                                       |
|          | remote | str  | remote location of file, no location means working directory (home or tmp if enabled) |

Return: None



**vagd.pwngd.Pwngd.system**

executes command on vm, interface to  `pwnlib.tubes.ssh.ssh.system`

Parameters:

| required | name | type | description              |
| -------- | ---- | ---- | ------------------------ |
| x        | cmd  | str  | command to execute on vm |

Return: `pwnlib.tubes.ssh.ssh.system`



**vagd.pwngd.Pwngd.debug** Experimental

Executes the provided binary with gdbserver on the vm and and attaches gdb.

Parameters:

| required | experimental | name      | type           | description                                                  |
| -------- | ------------ | --------- | -------------- | ------------------------------------------------------------ |
|          |              | argv      | list[str]      | command line arguments for binary                            |
|          |              | exe       | str            | exe to execute                                               |
|          |              | env       | Dict[str, str] | Environment variables to pass through to binary              |
|          |              | ssh       | Any            | ignored                                                      |
|          |              | gdbscript | str            | gdbscript to execute after gdb sessions hast attached to server |
|          | X            | api       | bool           | if a gdb python api interface should be created, is set as attribute `gdb` in return object |
|          | X            | sysroot   | str            | the sysroot to use for gdb. Not applicable if fast is set in Vagd constructor |
|          | X            | gdb_args  | list[str]      | additonal gdb command line arguments to add to gdb           |
|          |              | **kwargs  | Any            | allows the usage of other pwntool arguments                  |

Return: `pwn.process` 



**vagd.pwngd.Pwngd.process**

Executes the provided binary as process on vm

| required | name     | type      | description                                 |
| -------- | -------- | --------- | ------------------------------------------- |
|          | argv     | list[str] | command line arguments for binary           |
|          | **kwargs | Any       | allows the usage of other pwntool arguments |

Return: `pwn.process` 

**vagd.pwngd.pwngd.pwn_debug**

Executes the provided binary with gdbserver on the vm and and attaches gdb.

| required | name     | type      | description                                 |
| -------- | -------- | --------- | ------------------------------------------- |
|          | argv     | list[str] | command line arguments for binary           |
|          | **kwargs | Any       | allows the usage of other pwntool arguments |

Return: `pwn.process` 



**vagd.pwngd.Pwngd.start**

uses `pwn.args` to swap between `Vagd.process`, `Vagd.pwn_debug` and `Vagd.debug` if experimental is enabled (in constructor or via `ex=True`)

Parameters:

| required | experimental | name      | type      | description                                                  |
| -------- | ------------ | --------- | --------- | ------------------------------------------------------------ |
|          |              | argv      | list[str] | command line arguments for binary                            |
|          |              | gdbscript | str       | gdbscript to execute after gdb sessions hast attached to server |
|          | X            | api       | bool      | if a gdb python api interface should be created, is set as attribute `gdb` in return object |
|          | X            | sysroot   | str       | the sysroot to use for gdb. Not applicable if fast is set in Vagd constructor |
|          | X            | gdb_args  | list[str] | additonal gdb command line arguments to add to gdb           |
|          | X            | ex        | bool      | enables experimental features if not already enabled in constructor |
|          |              | **kwargs  | Any       | allows the usage of other pwntool arguments                  |

Return: `pwn.process` 

**vagd.wrapper.GDB**

receives `target: pwn.process` and returns gdb python api with type hinting from [types-gdb](https://pypi.org/project/types-gdb/) or a `wrapper.Empty` object, that returns None for every methode.

| required | name   | type        | description                                                  |
| -------- | ------ | ----------- | ------------------------------------------------------------ |
| x        | target | pwn.process | a pwn.process object. If tehe gdb attribute is set a gdb python api is returned, else wrapper.Empty |

Return: gdb python api or wrapper.Empty

**vagd.gdb**

Empty module, can be used for gdb type hinting

## Boxes

the following boxes were tested and work, box constants are inside `vagd.box`

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


currently only distributions that use `apt` are supported



## Future plans

### pre configured Vagrant boxes / QEMU Images / Docker Image

created pre configured Vagrant boxes with preinstalled lib debug symbols and gdbserver to lower init runtime.

### Docker integration

created a Docker integration that allows loading existing Dockerfiles, also add a feature that additionally virtualizes (Vagrant/Qemu) them to change the used kernel.

#### SSH integration

Add a ssh integration to allows specifying a remote machine with hostname, port, user and keyfile. ssh config integration would be nice.
