import os
import pwn
import pathlib
from shutil import which
from abc import ABC, abstractmethod
from typing import Union, Dict, Iterable


class Pwngd(ABC):
    LOCAL_DIR = './.vagd/'
    HOME_DIR = os.path.expanduser('~/.vagd/')
    SYSROOT = LOCAL_DIR + 'sysroot/'
    SYSROOT_LIB = SYSROOT + 'lib/'
    SYSROOT_LIB_DEBUG = SYSROOT + 'lib/debug'
    KEYFILE = HOME_DIR + 'keyfile'
    PUBKEYFILE = KEYFILE + '.pub'
    DEFAULT_PORT = 2222
    STATIC_GDBSRV_PORT = 42069

    _path: str
    _gdbsrvport: int
    _binary: str
    _ssh: pwn.ssh
    _experimental: bool
    _fast: bool

    @abstractmethod
    def _vm_setup(self) -> None:
        """
        setup vagrant machine creates new one if no Vagrantfile is specified or box does not match
        """
        pass

    @abstractmethod
    def _ssh_setup(self) -> None:
        """
        setup ssh connection
        """
        pass

    def _sync(self, file: str) -> None:
        """
        upload file on remote if not exist
        :type file: file to upload
        """
        sshpath = pwn.SSHPath(os.path.basename(file))
        if not sshpath.exists():
            self.put(file)

    _SSHFS_TEMPLATE = \
        'sshfs -p {port} -o StrictHostKeyChecking=no,ro,IdentityFile={keyfile} {user}@{host}:{remote_dir} {local_dir}'

    def _mount(self, remote_dir: str, local_dir: str) -> None:
        """
        mount remote dir on local wiith sshfs
        :param remote_dir: directory on remote to mount
        :param local_dir: local mount point
        """
        if not which('sshfs'):
            pwn.log.error('sshfs isn\'t installed')
        cmd = Pwngd._SSHFS_TEMPLATE.format(port=self._ssh.port,
                                           keyfile=self._ssh.keyfile,
                                           user=self._ssh.user,
                                           host=self._ssh.host,
                                           remote_dir=remote_dir,
                                           local_dir=local_dir)
        pwn.log.info(cmd)
        os.system(cmd)

    def _mount_lib(self, remote_lib: str = '/usr/lib') -> None:
        """
        mount the lib directory of remote
        """
        if not (os.path.exists(Pwngd.SYSROOT) and os.path.exists(Pwngd.SYSROOT_LIB)):
            os.makedirs(Pwngd.SYSROOT_LIB)
        if not os.path.ismount(Pwngd.SYSROOT_LIB):
            pwn.log.info('mounting libs in sysroot')
            self._mount(remote_lib, Pwngd.SYSROOT_LIB)

    def system(self, cmd: str) -> pwn.tubes.ssh.ssh_channel:
        """
        executes command on vm, interface to  pwnlib.tubes.ssh.ssh.system

        :param cmd: command to execute on vm
        :return: returns
        """
        return self._ssh.system(cmd)

    DEFAULT_PACKAGES = ['gdbserver', 'libc6-dbg']

    def _install_packages(self, packages: Iterable):
        """
        install packages on remote machine

        :param packages: packages to install on remote machine
        """
        self.system("sudo apt update").recvall()
        packages_str = " ".join(packages)
        self.system(f"sudo apt install -y {packages_str}").recvall()

    def put(self, file: str, remote: str = None):
        """
        upload file or vm on vm,

        :param file: file to upload
        :param remote: remote location of file, working directory if not specified
        :return: returns
        """
        if os.path.isdir(file):
            self._ssh.upload_dir(file, remote=remote)
        else:
            self._ssh.upload(file, remote=remote)

    def __init__(self,
                 binary: str,
                 files: Union[str, list[str]] = None,
                 packages: Iterable = None,
                 tmp: bool = False,
                 gdbsrvport: int = None,
                 fast: bool = False,
                 ex: bool = False):
        """
        Default init setups provided ssh machine

        :param binary: binary for VM debugging
        :param files: other files or directories that need to be uploaded to VM
        :param packages: packages to install on vm
        :param tmp: if a temporary directory should be created for files
        :param gdbsrvport: specify static gdbserver port, REQURIES port forwarding to localhost
        :param fast: mounts libs locally for faster symbol extraction (experimental)
        :param ex: if experimental features should be enabled
        """

        if packages is not None:
            self._install_packages(packages)

        self._path = binary
        self._gdbsrvport = gdbsrvport
        self._binary = './' + os.path.basename(binary)

        self._fast = fast
        self._experimental = ex

        if self._fast:
            if self._experimental:
                self._mount_lib()
            else:
                pwn.error('requires experimental features, activate with ex=True')

        pwn.context.ssh_session = self._ssh
        if tmp:
            self._ssh.set_working_directory()

        self._sync(self._path)
        self.system('chmod +x ' + self._binary)

        # Copy files to remote
        if isinstance(files, str):
            self._sync(files)
        elif hasattr(files, '__iter__'):
            for file in files:
                self._sync(file)

    def debug(self,
              argv: list[str] = None,
              exe: str = '',
              env: Dict[str, str] = None,
              ssh=None,
              gdbscript: str = '',
              api: bool = False,
              sysroot: str = None,
              gdb_args: list[str] = None,
              **kwargs) -> pwn.process:
        """
        run binary in vm with gdb and experimental features

        :param argv: command line arguments
        :param exe: exe to execute
        :param env: environment variable dictionary
        :param ssh: ignored self._ssh is used instead
        :param gdbscript: used gdbscript
        :param api: return gdb python api interface
        :param sysroot: sysroot directory
        :param gdb_args: additional gdb arguments
        :param kwargs: pwntool arguments
        :rtype: pwn.process
        """
        if argv is None:
            argv = []
        args = [self._binary, ] + argv
        if gdb_args is None:
            gdb_args = list()
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

        # set static port if wanted
        if self._gdbsrvport is not None:
            for i in range(len(args)):
                if args[i] == 'localhost:0':
                    args[i] = f':{self._gdbsrvport}'
                    break

        # Make sure gdbserver/qemu is installed
        if not which(args[0]):
            pwn.log.error("%s is not installed" % args[0])

        # Start gdbserver/qemu
        # (Note: We override ASLR here for the gdbserver process itself.)
        gdbserver = runner(args, env=env, aslr=1, **kwargs)

        # Set the .executable on the process object.
        gdbserver.executable = exe

        # Find what port we need to connect to
        port = pwn.gdb._gdbserver_port(gdbserver, ssh) if self._gdbsrvport is None else self._gdbsrvport

        host = '127.0.0.1'

        if self._fast:
            gdb_args += ["-ex", f"set sysroot {pathlib.Path().resolve()}/{Pwngd.SYSROOT}"]
            gdbscript = f"set debug-file-directory {Pwngd.SYSROOT_LIB_DEBUG}\n" + gdbscript
        elif sysroot:
            gdb_args += ["-ex", f"set sysroot {sysroot}"]
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

    def pwn_debug(self, argv: list[str] = None, ssh=None, **kwargs) -> pwn.process:
        """
        run binary in vm with gdb (pwnlib feature set)

        :param argv: comandline arguments for binary
        :param ssh: ignored self._ssh is used instead
        :param kwargs: pwntool parameters
        :return: pwntools process
        """
        if argv is None:
            argv = list()
        return pwn.gdb.debug([self._binary] + argv, ssh=self._ssh, **kwargs)

    def process(self, argv: list[str] = None, **kwargs) -> pwn.process:
        """
        run binary in vm as process

        :param argv: comandline arguments for binary
        :param kwargs: pwntool parameters
        :return: pwntools process
        """
        if argv is None:
            argv = list()
        return self._ssh.process([self._binary] + argv, **kwargs)

    def start(self,
              argv: list[str] = None,
              gdbscript: str = '',
              api: bool = None,
              sysroot: str = None,
              gdb_args: list = None,
              **kwargs) -> pwn.process:
        """
        start binary on remote and return pwn.process

        :param argv: commandline arguments for binary
        :param gdbscript: GDB script for GDB
        :param api: if GDB API should be enabled (experimental)
        :param sysroot: sysroot dir (experimental)
        :param gdb_args: extra gdb args (experimental)
        :param kwargs: pwntool parameters
        :return: pwntools process, if api=True tuple with gdb api
        """
        if pwn.args.GDB:
            if self._experimental:
                return self.debug(argv=argv, gdbscript=gdbscript, gdb_args=gdb_args, sysroot=sysroot,
                                  api=api, **kwargs)
            else:
                if gdb_args or sysroot or api:
                    pwn.error('requires experimental features, activate with ex=True in constructor')
                return self.pwn_debug(argv=argv, gdbscript=gdbscript, sysroot=sysroot, **kwargs)
        else:
            return self.process(argv=argv, **kwargs)
