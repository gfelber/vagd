import os
import time
from typing import Any, Dict, List, Optional
from abc import abstractmethod

import docker
import podman
import pwnlib.context
import pwnlib.elf
import pwnlib.gdb

from vagd import helper, templates
from vagd.box import Box
from vagd.virts.pwngd import Pwngd
from vagd.virts.shgd import Shgd


def _stop_for_debugger(aslr):
  # runs inside pwntools' remote execve wrapper right before execve.
  # Allow any process to ptrace us (Yama ptrace_scope=1) and wait for gdb.
  import ctypes
  import os
  import signal

  libc = ctypes.CDLL(None, use_errno=True)
  if not aslr:
    ADDR_NO_RANDOMIZE = 0x0040000
    libc.personality(ADDR_NO_RANDOMIZE)
  PR_SET_PTRACER = 0x59616D61
  PR_SET_PTRACER_ANY = ctypes.c_ulong(-1)
  libc.prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
  os.kill(os.getpid(), signal.SIGSTOP)


class Cogd(Shgd):
  """
  | Container virtualization for pwntools

  :param binary: binary to execute
  :param containerhome: home directory of container runtime
  :param lockfile: lockfile of container runtime
  :param cogd_type: type of container tool
  :param image: docker base image
  :param user: name of user on docker container
  :param forward: Dictionary of forwarded ports, needs to follow docker api format: 'hostport/(tcp|udp)' : guestport
  :param packages: packages to install on the container
  :param cap_add: Linux capabilities to add to the container
  :param privileged: run the container with extended privileges
  :param symbols: additionally install libc6 debug symbols (also updates libc6)
  :param ex: if experimental features, e.g. alpine, gdbserver should be enabled
  :param rm: remove container after exit
  :param alpine: if the conainter is alpine (also autochecks image name)
  :param fast: mounts libs locally for faster symbol extraction (experimental) NOT COMPATIBLE WITH ALPINE
  :param native: attach the host gdb directly to the process instead of using gdbserver (requires same uid)
  :param kwargs: parameters to pass through to super
  """

  _image: str
  _name: str
  _user: str
  _port: int
  _packages: List[str]
  _client: docker.DockerClient | podman.PodmanClient
  _id: str
  _containerdir: str
  _dockerfile: str
  _has_not_apt: bool
  _rm: bool
  _ex: bool
  _forward: Dict[str, int]
  _symbols: bool
  _i386: bool
  _template: str
  _containerhome: str
  _lockfile: str
  _type: str
  _native: bool
  _native_ok: Optional[bool] = None

  VAGD_PREFIX = "vagd-"
  DEFAULT_USER = "vagd"
  DEFAULT_PORT = 2222
  DEFAULT_IMAGE = Box.DOCKER_NOBLE

  DEFAULT_PACKAGES = Shgd.DEFAULT_PACKAGES + ["openssh-server"]

  def __init__(
    self,
    binary: str,
    containerhome: str,
    cogd_type: str,
    lockfile: str,
    image: str = DEFAULT_IMAGE,
    user: str = DEFAULT_USER,
    forward: Optional[Dict[str, int]] = None,
    packages: Optional[List[str]] = None,
    cap_add: Optional[List[str]] = None,
    privileged: bool = False,
    symbols: bool = True,
    rm: bool = True,
    ex: bool = False,
    fast: bool = False,
    alpine: bool = False,
    native: bool = True,
    **kwargs: Any,
  ):
    self._image = image
    self._native = native
    self._name = Cogd.VAGD_PREFIX + os.path.basename(binary)
    self._packages = list(Cogd.DEFAULT_PACKAGES)
    self._cap_add = list(cap_add or [])
    self._privileged = privileged
    self._containerhome = containerhome
    self._lockfile = lockfile
    self._type = cogd_type

    if symbols:
      helper.warn(
        f"installing {Pwngd.LIBC6_DEBUG} might update libc binary, consider using symbols=False"
      )
      self._packages.append(Pwngd.LIBC6_DEBUG)

    self._has_not_apt = True
    if alpine or "alpine" in image.lower():
      self._template = templates.DOCKER_ALPINE_TEMPLATE
    elif "arch" in image.lower() or "manjaro" in image.lower():
      self._template = templates.DOCKER_ARCH_TEMPLATE
    else:
      self._template = templates.DOCKER_TEMPLATE
      self._has_not_apt = False

    if packages is not None:
      if self._has_not_apt:
        helper.error("additional package installation not supported for alpine")

    # 32 bit binaries need the i386 libc on 64 bit images
    self._i386 = False
    if not self._has_not_apt:
      try:
        self._i386 = "i386" in pwnlib.elf.ELF(binary, checksec=False).arch
      except Exception:
        helper.warn("failed to get architecture from binary")
      if self._i386:
        self._packages.append(Pwngd.LIBC6_I386)

    self._containerdir = self._containerhome + f"{self._image}/"
    if not (os.path.exists(self._containerhome) and os.path.exists(self._containerdir)):
      os.makedirs(self._containerdir)
    self._dockerfile = self._containerdir + "Dockerfile"
    self._user = user
    self._forward = forward
    self._rm = rm
    self._ex = ex
    self._symbols = symbols
    if self._has_not_apt and not self._ex:
      helper.error("Docker alpine images requires experimental features")
    if self._forward is None:
      self._forward = dict()

    self._vm_setup()

    super().__init__(
      binary=binary,
      user=self._user,
      port=self._port,
      packages=packages,
      ex=ex,
      fast=fast,
      symbols=False,
      **kwargs,
    )

  def _create_dockerfile(self):
    helper.info(f"create new Dockerfile at {self._dockerfile}")
    if not os.path.exists(Pwngd.KEYFILE):
      helper.generate_keypair()

    if not os.path.exists(self._containerdir + "keyfile.pub"):
      os.link(Pwngd.PUBKEYFILE, self._containerdir + "keyfile.pub")

    with open(self._dockerfile, "w") as dockerfile:
      dockerfile.write(
        self._template.format(
          image=self._image,
          lock=templates.LOCK_PACKAGES if self._symbols else "",
          packages=" ".join(self._packages),
          user=self._user if self._user != "root" else Cogd.DEFAULT_USER,
          uid=os.getuid(),
          gid=os.getgid(),
          keyfile=os.path.basename(self._containerdir + "keyfile.pub"),
        )
      )

  def _create_container_instance(self):
    self.is_new = True
    helper.info("starting container instance")
    self._port = helper.first_free_port(Cogd.DEFAULT_PORT)
    self._forward.update({"22/tcp": ("127.0.0.1", self._port)})

    dir = os.path.dirname(os.path.realpath(__file__))
    with open(dir[: dir.rfind("/")] + "/res/seccomp.json", "r") as seccomp_file:
      seccomp_rules = seccomp_file.read().strip()

    container = self._client.containers.run(
      self._bimage,
      name=self._name,
      ports=self._forward,
      detach=True,
      remove=self._rm,
      cap_add=self._cap_add,
      privileged=self._privileged,
      security_opt=[f"seccomp:{seccomp_rules}"],
    )
    self._id = container.id
    helper.info(f"started container instance {container.short_id}")
    with open(self._lockfile, "w") as lockfile:
      lockfile.write(f"{container.id}:{str(self._port)}")

  def _build_image(self):
    build_progress = helper.progress("building docker image")
    hash = self._image.find("@")
    if hash != -1:
      tag = self._image[:hash].replace(":", "_")
      # add first 8 characters of hash
      tag += self._image[self._image.rfind(":") :][:8]
    else:
      tag = self._image

    if self._symbols:
      if ":" not in tag:
        tag += ":"
      else:
        tag += "_"
      tag += "symbols"

    if self._i386:
      tag += "_i386" if ":" in tag else ":i386"

    bimage = self._client.images.build(
      path=os.path.dirname(self._dockerfile), dockerfile=self._dockerfile, tag=f"vagd/{tag}"
    )[0]

    build_progress.success("done")

    return bimage

  def _vm_setup(self) -> None:
    self._client = self._client_setup()
    if not os.path.exists(self._lockfile):
      helper.info(f"No Lockfile {self._lockfile} found, creating new Container Instance")
      self._vm_create()
    else:
      with open(self._lockfile, "r") as lockfile:
        data = lockfile.readline().split(":")
        self._id = data[0]
        self._port = int(data[1])
      if not self._client.containers.list(filters={"id": self._id}):
        helper.info(f"Lockfile {self._lockfile} found, container not running, creating new one")
        self._vm_create()
      else:
        helper.info(
          f"Lockfile {self._lockfile} found, Docker Instance f{self._client.containers.get(self._id).short_id}"
        )

  def _vm_create(self):
    self._lock(self._type)

    if not os.path.exists(Pwngd.LOCAL_DIR):
      os.makedirs(Pwngd.LOCAL_DIR)

    # enfore changes to Dockerfile are always rebuild by docker
    self._create_dockerfile()

    self._bimage = self._build_image()

    self._create_container_instance()

  @abstractmethod
  def _client_setup(self) -> Any:
    pass

  def _init_pid(self) -> int:
    """host pid of the container's init process"""
    return int(self._client.containers.get(self._id).attrs["State"]["Pid"])

  @staticmethod
  def _status(pid: int) -> Dict[str, str]:
    """parse /proc/<pid>/status"""
    with open(f"/proc/{pid}/status") as status:
      return dict(line.rstrip("\n").split(":\t", 1) for line in status if ":\t" in line)

  def _host_pid(self, pid: int) -> Optional[int]:
    """
    translate a pid inside the container to a host pid

    :param pid: pid inside the container
    :return: host pid or None if not found
    """
    init = self._init_pid()
    for entry in os.listdir("/proc"):
      if not entry.isdigit():
        continue
      try:
        status = self._status(int(entry))
        if int(status["NSpid"].split()[-1]) != pid:
          continue
        # make sure the process actually belongs to our container
        parent = int(status["PPid"])
        while parent > 1 and parent != init:
          parent = int(self._status(parent)["PPid"])
      except (OSError, KeyError, ValueError):
        continue
      if parent == init:
        return int(entry)
    return None

  def _child_pid(self, parent: int, tries: int = 200) -> Optional[int]:
    """host pid of the first child of a host process, polls while the child is spawned"""
    for _ in range(tries):
      for entry in os.listdir("/proc"):
        try:
          if entry.isdigit() and int(self._status(int(entry))["PPid"]) == parent:
            return int(entry)
        except (OSError, KeyError, ValueError):
          continue
      time.sleep(0.01)
    return None

  def _native_supported(self) -> bool:
    """check if the host gdb is allowed to ptrace processes inside the container"""
    try:
      with open("/proc/sys/kernel/yama/ptrace_scope") as scope:
        if int(scope.read()) > 1:
          helper.warn("kernel.yama.ptrace_scope > 1, native attach requires CAP_SYS_PTRACE")
          return False
    except OSError:
      pass
    # rootless container runtimes map the container root to the host user
    if os.access(f"/proc/{self._init_pid()}/root", os.R_OK):
      return True
    # ptrace requires matching uid and primary gid
    uid, gid = (int(x) for x in self.system("id -u; id -g").recvall().split())
    if (uid, gid) == (os.getuid(), os.getgid()):
      return True
    helper.warn(
      f"container uid/gid {uid}/{gid} differs from host {os.getuid()}/{os.getgid()}, using gdbserver"
    )
    return False

  def process(
    self,
    argv: Optional[list[str]] = None,
    socket: Optional[bool] = None,
    native: Optional[bool] = None,
    **kwargs: Any,
  ) -> pwnlib.tubes.tube.tube:
    """
    run binary in container as process

    :param argv: comandline arguments for binary
    :param socket: override the instance's socket transport setting
    :param native: ignored, only relevant for debug
    :param kwargs: pwntool parameters
    :return: pwntools process
    """
    return super().process(argv=argv, socket=socket, **kwargs)

  def debug(
    self,
    argv: Optional[list[str]] = None,
    gdb_args: Optional[list[str]] = None,
    gdbscript: str = "",
    sysroot: Optional[str] = None,
    sysroot_debug: Optional[str] = None,
    socket: Optional[bool] = None,
    native: Optional[bool] = None,
    api: bool = False,
    **kwargs: Any,
  ) -> pwnlib.tubes.tube.tube:
    """
    run binary in container with gdb, attaches the host gdb directly if possible

    :param argv: comandline arguments for binary
    :param gdb_args: gdb args to forward to gdb
    :param gdbscript: GDB script for GDB
    :param sysroot: sysroot dir (ignored for native attach)
    :param sysroot_debug: sysroot debug lib dir (ignored for native attach)
    :param socket: override the instance's socket transport setting
    :param native: override the instance's native attach setting
    :param api: if GDB API should be enabled
    :param kwargs: pwntool parameters
    :return: pwntools process
    """
    if native is None:
      native = self._native
    if socket is None:
      socket = self._socket
    if native and self._native_ok is None:
      self._native_ok = self._native_supported()
    if not (native and self._native_ok):
      return super().debug(
        argv=argv,
        gdb_args=gdb_args,
        gdbscript=gdbscript,
        sysroot=sysroot,
        sysroot_debug=sysroot_debug,
        socket=socket,
        api=api,
        **kwargs,
      )

    if sysroot is not None:
      helper.warn("native attach uses the container root as sysroot, sysroot is ignored")

    aslr = kwargs.get("aslr")
    if aslr is None:
      aslr = pwnlib.context.context.aslr
    tube = self._transport(socket).process(
      [self._binary] + list(argv or ()),
      preexec_fn=_stop_for_debugger,
      preexec_args=(bool(aslr),),
      **kwargs,
    )
    if socket:
      # socat forks the execve wrapper as its child
      socat = self._host_pid(tube.socat.pid)
      hostpid = self._child_pid(socat) if socat else None
    else:
      hostpid = self._host_pid(tube.pid)
    if hostpid is None:
      tube.close()
      helper.error("could not find the host pid of the process")

    # wait until the wrapper stopped itself, the ptrace exception is in place by then
    for _ in range(200):
      if self._status(hostpid).get("State", "").startswith("T"):
        break
      time.sleep(0.01)
    else:
      helper.warn("process didn't stop, attaching anyway")

    helper.info(f"attaching gdb natively to host pid {hostpid}")
    root = f"/proc/{hostpid}/root"
    gdbscript = (
      "handle SIGSTOP nostop noprint\n"
      "tcatch exec\n"
      "continue\n"
      "handle SIGSTOP stop print\n"
      f"set debug-file-directory {root}/usr/lib/debug\n"
    ) + gdbscript
    result = pwnlib.gdb.attach(
      hostpid,
      exe=self._path,
      gdbscript=gdbscript,
      gdb_args=list(gdb_args or ()),
      sysroot=root,
      api=api,
    )
    if api:
      _, tube.gdb = result
    return tube
