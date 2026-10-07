import os
import shlex
from abc import ABC, abstractmethod
from shutil import which
from typing import Iterable, List, Sequence, Union, Optional, Any

import pwnlib.args
import pwnlib.filesystem
import pwnlib.gdb
import pwnlib.tubes

from vagd import helper
from vagd.patch import patch_binary


class Pwngd(ABC):
  """
  start binary on remote and return pwnlib.tubes.process.process

  :param binary: binary for VM debugging
  :param libs: download libraries (using ldd) from VM
  :param files: other files or directories that need to be uploaded to VM
  :param libraries: local shared libraries used to patch the binary
  :param interpreter: local ELF interpreter used to patch the binary
  :param packages: packages to install on vm
  :param symbols: additionally install libc6 debug symbols
  :param tmp: if a temporary directory should be created for files
  :param gdbsrvport: specify static gdbserver port, REQURIES port forwarding to localhost
  :param socket: expose the process through a one-shot TCP socket
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
  _socket: bool

  def __init__(
    self,
    binary: str,
    libs: bool = False,
    files: Optional[Union[str, list[str]]] = None,
    libraries: Optional[Sequence[str]] = None,
    interpreter: Optional[str] = None,
    packages: Optional[List[str]] = None,
    symbols: bool = True,
    tmp: bool = False,
    gdbsrvport: int = 0,
    root: bool = False,
    fast: bool = False,
    ex: bool = False,
    socket: bool = False,
  ):
    try:
      patched_libraries, patched_interpreter = patch_binary(binary, libraries, interpreter)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
      helper.error(str(error))

    self._path = binary
    self._gdbsrvport = gdbsrvport
    self._binary = "./" + os.path.basename(binary)
    self._socket = socket

    pwnlib.context.context.ssh_session = self._ssh

    if tmp:
      self._ssh.set_working_directory()

    patched = bool(patched_libraries or patched_interpreter)
    if patched:
      # A previous persistent VM may already contain an unpatched copy.
      self.put(self._path, remote=self._binary)
      self._system_checked(f"chmod 755 -- {shlex.quote(self._binary)}")
    elif self._sync(self._path):
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

    if patched:
      self._patch_remote(patched_libraries, patched_interpreter)

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

  def _transport(self, socket: bool = False) -> Any:
    """Return the process transport supplied by the concrete backend."""
    if socket:
      helper.error(f"socket transport is not supported by {type(self).__name__}")
    return self._ssh

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

  def _patch_remote(
    self, libraries: Sequence[str], interpreter: Optional[str]
  ) -> None:
    """Upload the artifacts used by the already-patched local executable."""
    artifacts = list(libraries)
    if interpreter:
      artifacts.append(interpreter)

    remote_artifacts = []
    for artifact in artifacts:
      remote = "./" + os.path.basename(artifact)
      self.put(artifact, remote=remote)
      remote_artifacts.append(remote)

    quoted_artifacts = " ".join(shlex.quote(path) for path in remote_artifacts)
    self._system_checked(f"chmod 755 -- {quoted_artifacts}")

  def _system_checked(self, command: str) -> bytes:
    """Run a remote command and report its output when it fails."""
    channel = self.system(command)
    output = channel.recvall()
    if channel.returncode:
      message = output.decode(errors="replace").strip()
      helper.error(f"remote command failed ({command}): {message}")
    return output

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
    socket: Optional[bool] = None,
    **kwargs: Any,
  ) -> pwnlib.tubes.tube.tube:
    """
    run binary in vm with gdb (pwnlib feature set)

    :param argv: comandline arguments for binary
    :param gdb_args: gdb args to forward to gdb
    :param gdbscript: GDB script for GDB
    :param sysroot: sysroot dir
    :param sysroot_debug: sysroot debug lib dir
    :param socket: override the instance's socket transport setting
    :param kwargs: pwntool parameters
    :return: pwntools process
    """
    if argv is None:
      argv = list()

    # pwnlib accepts a mutable list here, but callers commonly reuse it for
    # multiple backends. Never append our arguments to the caller's object.
    gdb_args = list(gdb_args or ())

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

    if socket is None:
      socket = self._socket
    ssh = self._transport(socket)

    return pwnlib.gdb.debug(
      [self._binary] + argv,
      ssh=ssh,
      gdb_args=gdb_args,
      port=self._gdbsrvport,
      gdbscript=gdbscript,
      sysroot=sysroot,
      **kwargs,
    )

  def process(
    self, argv: Optional[list[str]] = None, socket: Optional[bool] = None, **kwargs: Any
  ) -> pwnlib.tubes.tube.tube:
    """
    run binary in vm as process

    :param argv: comandline arguments for binary
    :param socket: override the instance's socket transport setting
    :param kwargs: pwntool parameters
    :return: pwntools process
    """
    if argv is None:
      argv = list()
    if socket is None:
      socket = self._socket
    ssh = self._transport(socket)
    return ssh.process([self._binary] + argv, **kwargs)

  def start(
    self,
    argv: list[str] = None,
    gdbscript: str = "",
    api: bool = False,
    sysroot: Optional[str] = None,
    sysroot_debug: Optional[str] = None,
    gdb_args: Optional[list[str]] = None,
    socket: Optional[bool] = None,
    **kwargs: Any,
  ) -> pwnlib.tubes.tube.tube:
    """
    start binary on remote and return pwnlib.tubes.process.process

    :param argv: commandline arguments for binary
    :param gdbscript: GDB script for GDB
    :param api: if GDB API should be enabled
    :param sysroot: sysroot dir
    :param sysroot_debug: sysroot debug lib dir
    :param gdb_args: extra gdb args
    :param socket: override the instance's socket transport setting
    :param kwargs: pwntool parameters
    :return: pwntools process, if api=True tuple with gdb api
    """
    if pwnlib.args.args.GDB:
      return self.debug(
        argv=argv,
        gdbscript=gdbscript,
        gdb_args=gdb_args,
        sysroot=sysroot,
        socket=socket,
        api=api,
        **kwargs,
      )
    else:
      return self.process(argv=argv, socket=socket, **kwargs)
