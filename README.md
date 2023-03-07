# VAGD

Vagrant integration in pwntools

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

use *template.py* and copy it to *exploit.py* fill out the constants

```bash
# run as process in VM
./exploit.py
# run as gdb server in VM requires tmux
./exploit.py GDB
# run on remote IP:PORT
./exploit.py REMOTE
```

I recommend using [pwndbg](https://github.com/pwndbg/pwndbg).

## Features

**vagd.Vagd**

Constructor for Vagd, initializes a new vagrant machine (if non existent)

Parameters:

| required | experimental | name        | type         | description                                                  |
| -------- | ------------ | ----------- | ------------ | ------------------------------------------------------------ |
| X        |              | binary      | str          | binary to debug on  vagrant vm                               |
|          |              | vagrantfile | str          | location of Vagrantfile                                      |
|          |              | vbox        | str          | vagrant box to use                                           |
|          |              | files       | str \| tuple | other files to upload to vm, all files are uploaded to current working directory (home or tmp) |
|          |              | tmp         | bool         | if the created directory in the vm should be temporary, requires new upload after each execution |
|          | X            | fast        | bool         | fast debug, mounts library files locally with **sshfs** in newly created directory ./sysroot/lib/ for faster symbol reading |
|          | x            | ex          | bool         | enables experimental features for the whole object           |



**vagd.Vagd.put**

upload file or directory to vm

Parameters:

| required | name   | type | description                                                  |
| -------- | ------ | ---- | ------------------------------------------------------------ |
| x        | file   | str  | path of file to upload                                       |
|          | remote | str  | remote location of file, no location means working directory (home or tmp if enabled) |

Return: None



**vagd.Vagd.system**

executes command on vm, interface to  `pwnlib.tubes.ssh.ssh.system`

Parameters:

| required | name | type | description              |
| -------- | ---- | ---- | ------------------------ |
| x        | cmd  | str  | command to execute on vm |

Return: `pwnlib.tubes.ssh.ssh.system`



**vagd.Vagd.debug** Experimental

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



**vagd.Vagd.process**

Executes the provided binary as process on vm

| required | name     | type      | description                                 |
| -------- | -------- | --------- | ------------------------------------------- |
|          | argv     | list[str] | command line arguments for binary           |
|          | **kwargs | Any       | allows the usage of other pwntool arguments |

Return: `pwn.process` 

**vagd.Vagd.pwn_debug**

Executes the provided binary with gdbserver on the vm and and attaches gdb.

| required | name     | type      | description                                 |
| -------- | -------- | --------- | ------------------------------------------- |
|          | argv     | list[str] | command line arguments for binary           |
|          | **kwargs | Any       | allows the usage of other pwntool arguments |

Return: `pwn.process` 



**vagd.Vagd.start**

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

* ubuntu/jammy64
* ubuntu/focal64
* ubuntu/bionic64
* ubuntu/xenial64

currently Vagrantfile generation is only compatible distributions that use `apt`



## Future plans

### pre configured Vagrant boxes

created pre configured Vagrant boxes with preinstalled lib debug symbols and gdbserver to lower runtime.

### Template generation

in order to get template.py u either need to download the file manually or download the repo. If possible the option of generating a template with `python -m vagd` should be added.

### package installation

It should be possible to specify a list of packages in the Vagd constructor that are to be installed. It should also be checked if provided packages are already installed inside of the vm.
