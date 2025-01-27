import os
from abc import ABC, abstractmethod
from shutil import which
from typing import Iterable, List, Union, Optional, Any

import pwnlib.args
import pwnlib.filesystem
import pwnlib.gdb
import pwnlib.tubes

from vagd import helper


class Pwngd(ABC):
  """
  start binary on remote and return pwnlib.tubes.process.process

  :param binary: binary for VM debugging
  :param libs: download libraries (using ldd) from VM
  :param files: other files or directories that need to be uploaded to VM
  :param packages: packages to install on vm
  :param symbols: additionally install libc6 debug symbols
  :param tmp: if a temporary directory should be created for files
  :param gdbsrvport: specify static gdbserver port, REQURIES port forwarding to localhost
  :param fast: mounts libs locally for faster symbol extraction (experimental)
  :param ex: if experimental features should be enabled
  """

  LOCAL_DIR = "./.vagd/"
  HOME_DIR = os.path.expanduser("~/.local/share/vagd/")
  SYSROOT = LOCAL_DIR + "sysroot/"
  SYSROOT_LIB_DEBUG = SYSROOT + "lib/debug"
  LOCKFILE = LOCAL_DIR + "vagd.lock"
  KEYFILE = HOME_DIR + "keyfile"
  PUBKEYFILE = KEYFILE + ".pub"
  DEFAULT_PORT = 2222
  STATIC_GDBSRV_PORT = 42069

  is_new: bool = False
  _path: str
  _gdbsrvport: int
  _binary: str
  _ssh: pwnlib.tubes.ssh.ssh
  _experimental: bool
  _fast: bool

  def __init__(
    self,
    binary: str,
    libs: bool = False,
    files: Optional[Union[str, list[str]]] = None,
    packages: Optional[List[str]] = None,
    symbols: bool = True,
    tmp: bool = False,
    gdbsrvport: int = 0,
    root: bool = False,
    fast: bool = False,
    ex: bool = False,
  ):
    self._path = binary
    self._gdbsrvport = gdbsrvport
    self._binary = "./" + os.path.basename(binary)

    pwnlib.context.context.ssh_session = self._ssh

    if tmp:
      self._ssh.set_working_directory()

    if self._sync(self._path):
      self.system("chmod +x " + self._binary)

    if self.is_new and libs:
      if not (os.path.exists(Pwngd.LIBS_DIRECTORY)):
        os.makedirs(Pwngd.LIBS_DIRECTORY)

      self.libs(Pwngd.LIBS_DIRECTORY)

    if self.is_new and packages is not None:
      if symbols:
        packages.append(Pwngd.LIBC6_DEBUG)
      try:
        elf = pwnlib.elf.ELF(binary, checksec=False)
        if elf.arch == "i386":
          packages.append(Pwngd.LIBC6_I386)
      except:
        helper.warn("failed to get architecture from binary")
      self._install_packages(packages)

    self._fast = fast
    self._experimental = ex

    if self._fast:
      if self._experimental:
        self._mount_root()
      else:
        helper.error("requires experimental features, activate with ex=True")

    # Copy files to remote
    if isinstance(files, str):
      self._sync(files)
    elif hasattr(files, "__iter__"):
      for file in files:
        self._sync(file)

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

  def _sync(self, file: str) -> bool:
    """
    upload file on remote if not exist
    :type file: file to upload
    :return: if the file was uploaded
    """
    sshpath = pwnlib.filesystem.SSHPath(file)
    if not sshpath.exists():
      self.put(file)
      return True
    return False

  _SSHFS_TEMPLATE = "sshfs -p {port} -o StrictHostKeyChecking=no,ro,IdentityFile={keyfile} {user}@{host}:{remote_dir} {local_dir}"

  def _mount(self, remote_dir: str, local_dir: str) -> None:
    """
    mount remote dir on local wiith sshfs
    :param remote_dir: directory on remote to mount
    :param local_dir: local mount point
    """
    if not which("sshfs"):
      helper.error("sshfs isn't installed")
    cmd = Pwngd._SSHFS_TEMPLATE.format(
      port=self._ssh.port,
      keyfile=self._ssh.keyfile,
      user=self._ssh.user,
      host=self._ssh.host,
      remote_dir=remote_dir,
      local_dir=local_dir,
    )
    helper.info(cmd)
    os.system(cmd)

  def _lock(self, typ: str):
    if not os.path.exists(Pwngd.LOCAL_DIR):
      os.makedirs(Pwngd.LOCAL_DIR)

    with open(Pwngd.LOCKFILE, "w") as lfile:
      lfile.write(typ)

  def _mount_root(self, remote_lib: str = "/") -> None:
    """
    mount the lib directory of remote
    """
    if not os.path.exists(Pwngd.SYSROOT):
      os.makedirs(Pwngd.SYSROOT)
    if not os.path.ismount(Pwngd.SYSROOT):
      helper.info("mounting libs in sysroot")
      self._mount(remote_lib, Pwngd.SYSROOT)

  def system(self, cmd: str) -> pwnlib.tubes.ssh.ssh_channel:
    """
    executes command on vm, interface to  pwnlib.tubes.ssh.ssh.system

    :param cmd: command to execute on vm
    :return: returns
    """
    return self._ssh.system(cmd)

  DEFAULT_PACKAGES = ["gdbserver", "python3", "sudo"]
  LIBC6_DEBUG = "libc6-dbg"
  LIBC6_I386 = "libc6-i386"

  def _install_packages(self, packages: Iterable[str]):
    """
    install packages on remote machine

    :param packages: packages to install on remote machine
    """
    helper.info(f"installing packages: {' '.join(packages)}")
    self.system("sudo apt update").recvall()
    packages_str = " ".join(packages)
    self.system(f"sudo DEBIAN_FRONTEND=noninteractive apt install -y {packages_str}").recvall()

  def put(self, file: str, remote: Optional[str] = None):
    """
    upload file or dir on vm,

    :param file: file to upload
    :param remote: remote location of file, working directory if not specified
    :return: returns
    """
    if os.path.isdir(file):
      self._ssh.upload_dir(file, remote=remote)
    else:
      self._ssh.upload(file, remote=remote)

  def pull(self, file: str, local: Optional[str] = None):
    """
    download file or dir on vm,

    :param file: remote location of file, working directory if not specified
    :param local: local location of file, current directory if not specified
    :return: returns
    """
    sshpath = pwnlib.filesystem.SSHPath(os.path.basename(file))
    if sshpath.is_dir():
      self._ssh.download_dir(file, local=local)
    else:
      self._ssh.download_file(file, local=local)

  LIBS_DIRECTORY = "libs"

  def libs(self, directory: str):
    """
    Downloads the libraries referred to by a file.
    This is done by running ldd on the remote server, parsing the output and downloading the relevant files.

    directory(str): Output directory
    :return:
    """
    for lib in self._ssh._libs_remote(self._binary).keys():
      self.pull(lib, directory + "/" + os.path.basename(lib))

  def debug(
    self,
    argv: Optional[list[str]] = None,
    gdb_args: Optional[list[str]] = None,
    gdbscript: str = "",
    sysroot: Optional[str] = None,
    sysroot_debug: Optional[str] = None,
    **kwargs: Any,
  ) -> pwnlib.tubes.ssh.ssh_channel:
    """
    run binary in vm with gdb (pwnlib feature set)

    :param argv: comandline arguments for binary
    :param gdb_args: gdb args to forward to gdb
    :param gdbscript: GDB script for GDB
    :param sysroot: sysroot dir
    :param sysroot_debug: sysroot debug lib dir
    :param kwargs: pwntool parameters
    :return: pwntools process
    """
    if argv is None:
      argv = list()

    if gdb_args is None:
      gdb_args = list()

    if self._fast:
      if sysroot is not None:
        helper.warn("fast enabled but sysroot set, sysroot is ignored")
      sysroot = Pwngd.SYSROOT

    if sysroot_debug is not None and sysroot is None:
      helper.warn("sysroot_debug set, but sysroot isn't ignored")

    if sysroot is not None:
      if sysroot_debug == None:
        sysroot_debug = Pwngd.SYSROOT_LIB_DEBUG
      gdbscript = f"set debug-file-directory {sysroot_debug}\n" + gdbscript

    gdb_args += ["-ex", f"file -readnow {self._path}"]

    return pwnlib.gdb.debug(
      [self._binary] + argv,
      ssh=self._ssh,
      gdb_args=gdb_args,
      port=self._gdbsrvport,
      gdbscript=gdbscript,
      sysroot=sysroot,
      **kwargs,
    )

  def process(
    self, argv: Optional[list[str]] = None, **kwargs: Any
  ) -> pwnlib.tubes.ssh.ssh_channel:
    """
    run binary in vm as process

    :param argv: comandline arguments for binary
    :param kwargs: pwntool parameters
    :return: pwntools process
    """
    if argv is None:
      argv = list()
    return self._ssh.process([self._binary] + argv, **kwargs)

  def start(
    self,
    argv: list[str] = None,
    gdbscript: str = "",
    api: bool = False,
    sysroot: Optional[str] = None,
    sysroot_debug: Optional[str] = None,
    gdb_args: Optional[list[str]] = None,
    **kwargs: Any,
  ) -> pwnlib.tubes.ssh.ssh_channel:
    """
    start binary on remote and return pwnlib.tubes.process.process

    :param argv: commandline arguments for binary
    :param gdbscript: GDB script for GDB
    :param api: if GDB API should be enabled
    :param sysroot: sysroot dir
    :param sysroot_debug: sysroot debug lib dir
    :param gdb_args: extra gdb args
    :param kwargs: pwntool parameters
    :return: pwntools process, if api=True tuple with gdb api
    """
    if pwnlib.args.args.GDB:
      return self.debug(
        argv=argv,
        gdbscript=gdbscript,
        gdb_args=gdb_args,
        sysroot=sysroot,
        api=api,
        **kwargs,
      )
    else:
      return self.process(argv=argv, **kwargs)
