import os
import re
import pwn
import vagrant
import fileinput
from vagd import vtemplate, box
from typing import Collection, Union, Tuple, Dict

class Vagd:
    VAGRANTFILE_PATH = './Vagrantfile'
    VAGRANT_BOX = box.UBUNTU_FOCAL64

    _binary: str
    _box: str
    _vagrantfile: str
    _v: vagrant
    _ssh: pwn.ssh

    def _get_box(self) -> str:
        """
        returns box of current vagrantfile
        @:rtype box of Vagrantfile
        """
        with open(self._vagrantfile, 'r') as vagrantfile:
            for line in vagrantfile.readlines():
                if 'config.vm.box' in line:
                    pattern = r'config.vm.box = "(.*?)"'
                    match = re.search(pattern, line, re.DOTALL)
                    if match:
                        return match.group(1)
        return ''

    def _vagrant_setup(self) -> None:
        """
        setup vagrant machine creates new one if no Vagrantfile is specified or box does not match
        """

        if not os.path.isfile(self._vagrantfile):
            vagrant_config = vtemplate.VAGRANT_TEMPLATE.format(self._box)
            with open(self._vagrantfile, 'w') as file:
                file.write(vagrant_config)

        elif self._get_box() != self._box:
            self._v.destroy()
            for line in fileinput.input(self._vagrantfile, inplace=True):
                if 'config.vm.box' in line:
                    line = f'config.vm.box = "{self._box}"\n'
                print(line, end='')

        self._v.up()

    def _ssh_setup(self) -> None:
        """
        setup ssh connection to vagrant
        """
        self._ssh = pwn.ssh(
            user=self._v.user(),
            host=self._v.hostname(),
            port=int(self._v.port()),
            keyfile=self._v.keyfile(),
            ignore_config=True
        )

    def _sync(self, file: str) -> None:
        """
        check if file exists on remote and upload if not
        :rtype: None
        """
        _, status = self._ssh.run_to_end(f'test -e {os.path.basename(file)}')
        if status != 0:
            self._ssh.put(file)

    def __init__(self,
                 binary: str,
                 box: str = VAGRANT_BOX,
                 vagrantfile: str = VAGRANTFILE_PATH,
                 files: Union[str, tuple[str]] = tuple(),
                 tmp: bool = False):
        """

        :param binary: binary for VM debugging
        :param box: vagrant box to use
        :param vagrantfile: location of Vagrantfile
        :param files: other files or directory that need to be uploaded to VM
        """
        self._path = binary
        self._binary = './' + os.path.basename(binary)
        self._box = box
        self._vagrantfile = vagrantfile
        self._v = vagrant.Vagrant(self._vagrantfile.replace('Vagrantfile', ''))

        self._vagrant_setup()
        self._ssh_setup()
        if tmp:
            self._ssh.set_working_directory()

        self._sync(binary)
        self._ssh.system('chmod +x ' + self._binary)

        # Copy files to remote
        if isinstance(files, str):
            self._sync(files)
        elif isinstance(files, tuple):
            for file in files:
                self._sync(file)

    def debug(self, args, exe: str = '', env: Dict[str, str] = None,
              ssh=None, gdbscript: str = '', api: bool = False,
              sysroot: str = None, gdb_args: list = list(), **kwargs) -> pwn.process:
        """

        :param args: binary with command line arguments
        :param exe: exe to execute
        :param env: environment variable dictionary
        :param ssh: ignored self._ssh is used instead
        :param gdbscript: used gdbscript
        :param kwargs: pwntool arguments
        :return: Tuple with (pwn.process, pwn.gdb.Gdb)
        """
        pwn.log.warn('pwntools API for ssh isn\'t official supported')
        ssh = self._ssh
        if isinstance(args, (bytes, pwn.six.text_type)):
            args = [args]

        runner = pwn.gdb._get_runner(ssh)
        which = pwn.gdb._get_which(ssh)

        args, env = pwn.gdb.misc.normalize_argv_env(args, env, pwn.log)
        if env:
            env = {bytes(k): bytes(v) for k, v in env}

        args = pwn.gdb._gdbserver_args(args=args, which=which, env=env)

        # Make sure gdbserver/qemu is installed
        if not which(args[0]):
            pwn.log.error("%s is not installed" % args[0])

        # Start gdbserver/qemu
        # (Note: We override ASLR here for the gdbserver process itself.)
        gdbserver = runner(args, env=env, aslr=1, **kwargs)

        # Set the .executable on the process object.
        gdbserver.executable = exe

        # Find what port we need to connect to
        port = pwn.gdb._gdbserver_port(gdbserver, ssh)

        host = '127.0.0.1'

        gdbscript = "set debug-file-directory /usr/lib/debug\n" + gdbscript
        gdb_args += ["-ex", f"file -readnow {self._path}"]
        if sysroot:
            gdb_args += ["-ex", f"set sysroot = {sysroot}"]

        tmp = pwn.gdb.attach((host, port), exe=exe, gdbscript=gdbscript,
                             gdb_args=gdb_args, ssh=ssh, api=api)
        if api:
            _, gdb = tmp
            gdbserver.gdb = gdb

        # gdbserver outputs a message when a client connects
        garbage = gdbserver.recvline(timeout=1)

        # Some versions of gdbserver output an additional message
        garbage2 = gdbserver.recvline_startswith(b"Remote debugging from host ", timeout=2)

        return gdbserver

    def pwn_debug(self, argv: Collection = tuple(), *a, **kw) -> pwn.process:
        """
        run binary in vm with gdb (pwnlib feature set)
        :param argv: comandline arguments for binary
        :param a: pwntool parameters
        :param kw: pwntool parameters
        :return: pwntools process
        """
        return pwn.gdb.debug((self._binary,) + argv, ssh=self._ssh, *a, **kw)

    def process(self, argv: Collection = tuple(), *a, **kw) -> pwn.process:
        """
        run binary in vm as process
        :param argv: comandline arguments for binary
        :param a: pwntool parameters
        :param kw: pwntool parameters
        :return: pwntools process
        """
        return self._ssh.process((self._binary,) + argv, *a, **kw)

    def start(self, argv: Collection = tuple(), gdbscript: str = '', api: bool = None, sysroot: str = None,
              gdb_args: list = list(), pwnlib: bool = True, *a, **kw) -> pwn.process:
        """
        start binary on remote and return pwn.process
        :param argv: commandline arguments for binary
        :param gdbscript: GDB script for GDB
        :param api: if GDB API should be enabled
        :param a: pwntool parameters
        :param kw: pwntool parameters
        :return: pwntools process, if api=True tuple with gdb api
        """
        if pwn.args.GDB:
            if pwnlib:
                return self.pwn_debug(argv=argv, gdbscript=gdbscript, sysroot=sysroot, *a, **kw)
            else:
                return self.debug((self._binary,) + argv, gdbscript=gdbscript, gdb_args=gdb_args, sysroot=sysroot,
                                  api=api, *a, **kw)
        else:
            return self.process(argv=argv, *a, **kw)
