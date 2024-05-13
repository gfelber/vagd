import os
import re
import pwn
import vagrant
import fileinput
from shutil import which
from vagd import vtemplate, box
from typing import Union, Dict


class Vagd:
    VAGRANTFILE_PATH = './Vagrantfile'
    VAGRANTFILE_BOX = 'config.vm.box'
    VAGRANT_BOX = box.UBUNTU_FOCAL64
    SYSROOT = './sysroot/'
    SYSROOT_LIB = SYSROOT + 'lib/'

    _binary: str
    _box: str
    _vagrantfile: str
    _v: vagrant
    _ssh: pwn.ssh
    _experimental: bool

    def _get_box(self) -> str:
        """
        returns box of current vagrantfile
        @:rtype box str of Vagrantfile
        """
        with open(self._vagrantfile, 'r') as vagrantfile:
            for line in vagrantfile.readlines():
                if Vagd.VAGRANTFILE_BOX in line:
                    pattern = fr'{Vagd.VAGRANTFILE_BOX} = "(.*?)"'
                    match = re.search(pattern, line, re.DOTALL)
                    if match:
                        return match.group(1)
        return ''

    def _vagrant_setup(self) -> None:
        """
        setup vagrant machine creates new one if no Vagrantfile is specified or box does not match
        """

        if not os.path.isfile(self._vagrantfile):
            pwn.log.info('creating new Vagrantfile')
            vagrant_config = vtemplate.VAGRANT_TEMPLATE.format(self._box)
            with open(self._vagrantfile, 'w') as file:
                file.write(vagrant_config)
            pwn.log.info('initialing new vagrant vm might take a while')
            self._v.up()

        elif self._get_box() != self._box:
            pwn.log.info('new box detected destroying old machine')
            self._v.destroy()
            for line in fileinput.input(self._vagrantfile, inplace=True):
                if Vagd.VAGRANTFILE_BOX in line:
                    line = f'{Vagd.VAGRANTFILE_BOX} = "{self._box}"\n'
                print(line, end='')
            pwn.log.info('initialing new vagrant vm might take a while')
            self._v.up()

        if self._v.status()[0].state != 'running':
            pwn.log.info('starting existing vagrant machine')
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
        upload file on remote if not exist
        :type file: file to upload
        """
        sshpath = pwn.SSHPath(os.path.basename(file))
        if not sshpath.exists():
            self._ssh.put(file)

    SSHFS_TEMPLATE = \
        'sshfs -p {port} -o StrictHostKeyChecking=no,ro,IdentityFile={keyfile} {user}@{host}:{remote_dir} {local_dir}'

    def _mount(self, remote_dir: str, local_dir: str) -> None:
        """
        mount remote dir on local wiith sshfs
        :param remote_dir: directory on remote to mount
        :param local_dir: local mount point
        """
        if not which('sshfs'):
            pwn.log.error('sshfs isn\'t installed')
        os.system(Vagd.SSHFS_TEMPLATE.format(port=self._v.port(),
                                             keyfile=self._v.keyfile(),
                                             user=self._v.user(),
                                             host=self._v.hostname(),
                                             remote_dir=remote_dir,
                                             local_dir=local_dir))

    def _mount_lib(self, remote_lib: str = '/usr/lib') -> None:
        """
        mount the lib directory of remote
        """
        if not (os.path.exists(Vagd.SYSROOT) and os.path.exists(Vagd.SYSROOT_LIB)):
            os.makedirs(Vagd.SYSROOT_LIB)
        if not os.path.ismount(Vagd.SYSROOT_LIB):
            pwn.log.info('mounting libs in sysroot')
            self._mount(remote_lib, Vagd.SYSROOT_LIB)

    def __init__(self,
                 binary: str,
                 vbox: str = VAGRANT_BOX,
                 vagrantfile: str = VAGRANTFILE_PATH,
                 files: Union[str, tuple[str]] = tuple(),
                 tmp: bool = False,
                 fast: bool = False,
                 ex: bool = False):
        """

        :param binary: binary for VM debugging
        :param vbox: vagrant box to use
        :param vagrantfile: location of Vagrantfile
        :param files: other files or directories that need to be uploaded to VM
        :param tmp: if a temporary directory should be created for files
        :param fast: mounts libs locally for faster symbol extraction (experimental)
        :param ex: if experimental features should be enabled
        """
        if not which('vagrant'):
            pwn.log.error('vagrant isn\'t installed')

        self._path = binary
        self._binary = './' + os.path.basename(binary)
        self._box = vbox
        self._vagrantfile = vagrantfile
        self._v = vagrant.Vagrant(os.path.dirname(vagrantfile))
        self._fast = fast
        self._experimental = ex

        self._vagrant_setup()

        if self._fast:
            if self._experimental:
                self._mount_lib()
            else:
                pwn.error('requires experimental features, activate with ex=True')

        self._ssh_setup()

        pwn.context.ssh_session = self._ssh
        if tmp:
            self._ssh.set_working_directory()

        self._sync(self._path)
        self._ssh.system('chmod +x ' + self._binary)

        # Copy files to remote
        if isinstance(files, str):
            self._sync(files)
        elif isinstance(files, tuple):
            for file in files:
                self._sync(file)

    def debug(self,
              args,
              exe: str = '',
              env: Dict[str, str] = None,
              ssh=None,
              gdbscript: str = '',
              api: bool = False,
              sysroot: str = None,
              gdb_args: list = None,
              **kwargs) -> pwn.process:
        """
        run binary in vm with gdb and experimental features
        :param args: binary with command line arguments
        :param exe: exe to execute
        :param env: environment variable dictionary
        :param ssh: ignored self._ssh is used instead
        :param gdbscript: used gdbscript
        :param api: return gdb python api interface
        :param sysroot: sysroot directory
        :param gdb_args: additional gdb arguments
        :param kwargs: pwntool arguments
        :return: Tuple with (pwn.process, pwn.gdb.Gdb)
        """
        if gdb_args is None:
            gdb_args = tuple()
        pwn.log.warn('using experimental features')
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

        if self._fast:
            gdb_args += ["-ex", f"set sysroot = ./sysroot"]
            gdbscript = "set debug-file-directory ./sysroot/lib/debug\n" + gdbscript
        elif sysroot:
            gdb_args += ["-ex", f"set sysroot = {sysroot}"]
            gdbscript = f"set debug-file-directory ./{sysroot}/lib/debug\n" + gdbscript
        else:
            gdbscript = "set debug-file-directory /lib/debug\n" + gdbscript

        gdb_args += ["-ex", f"file -readnow {self._path}"]

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

    def pwn_debug(self, argv=None, **kw) -> pwn.process:
        """
        run binary in vm with gdb (pwnlib feature set)
        :param argv: comandline arguments for binary
        :param kw: pwntool parameters
        :return: pwntools process
        """
        if argv is None:
            argv = list()
        return pwn.gdb.debug((self._binary,) + argv, ssh=self._ssh, **kw)

    def process(self, argv=None, **kw) -> pwn.process:
        """
        run binary in vm as process
        :param argv: comandline arguments for binary
        :param kw: pwntool parameters
        :return: pwntools process
        """
        if argv is None:
            argv = list()
        return self._ssh.process((self._binary,) + argv, **kw)

    def start(self,
              argv: tuple = None,
              gdbscript: str = '',
              api: bool = None,
              sysroot: str = None,
              gdb_args: list = None,
              ex: bool = False,
              **kw) -> pwn.process:
        """
        start binary on remote and return pwn.process
        :param argv: commandline arguments for binary
        :param gdbscript: GDB script for GDB
        :param api: if GDB API should be enabled (experimental)
        :param sysroot: sysroot dir (experimental)
        :param gdb_args: extra gdb args (experimental)
        :param ex: enable experimental features (if not set in constructor)
        :param kw: pwntool parameters
        :return: pwntools process, if api=True tuple with gdb api
        """
        if gdb_args is None:
            gdb_args = list()
        if argv is None:
            argv = tuple()
        if pwn.args.GDB:
            if ex or self._experimental:
                return self.debug((self._binary,) + argv, gdbscript=gdbscript, gdb_args=gdb_args, sysroot=sysroot,
                                  api=api, **kw)
            else:
                if gdb_args or sysroot or api:
                    pwn.error('requires experimental features, activate with ex=True')
                return self.pwn_debug(argv=argv, gdbscript=gdbscript, sysroot=sysroot, **kw)
        else:
            return self.process(argv=argv, **kw)
