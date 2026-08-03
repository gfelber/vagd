import hashlib
import io
import json
import os
import re
import shlex
import tarfile
from typing import Any, Dict, List, Optional, Union

import docker
import pwnlib.args
import pwnlib.gdb

from vagd import helper, templates
from vagd.box import Box
from vagd.virts.docker_exec import DockerExecTube
from vagd.virts.pwngd import Pwngd


class Degd(Pwngd):
  """
  Native Docker API backend with Docker exec and gdbserver integration.

  :param binary: local binary to upload and execute
  :param image: Debian or Ubuntu base image
  :param user: user for target processes inside the container
  :param forward: additional Docker port mappings
  :param packages: additional packages installed while building the image
  :param cap_add: Linux capabilities to add to the container
  :param privileged: run the container with extended privileges
  :param symbols: install libc debug symbols
  :param files: additional files or directories to upload
  :param libs: download the target's dynamically linked libraries
  :param tmp: use a fresh temporary working directory
  :param rm: automatically remove the container when it stops
  """

  TYPE = "degd"
  LOCKFILE = Pwngd.LOCAL_DIR + "docker-api.lock"
  DOCKERHOME = Pwngd.HOME_DIR + "docker-api/"
  DEFAULT_IMAGE = Box.DOCKER_NOBLE
  DEFAULT_USER = "vagd"
  WORKDIR = "/vagd"
  GDBSERVER_PORT = 42069
  DEFAULT_PACKAGES = ["gdbserver", "python3", "sudo"]

  def __init__(
    self,
    binary: str,
    image: str = DEFAULT_IMAGE,
    user: str = DEFAULT_USER,
    forward: Optional[Dict[str, Any]] = None,
    packages: Optional[List[str]] = None,
    cap_add: Optional[List[str]] = None,
    privileged: bool = False,
    symbols: bool = True,
    files: Optional[Union[str, List[str]]] = None,
    libs: bool = False,
    tmp: bool = False,
    rm: bool = True,
    fast: bool = False,
    ex: bool = False,
    **kwargs: Any,
  ):
    del fast, ex
    if kwargs:
      helper.error(f"unsupported Degd arguments: {', '.join(kwargs)}")
    if "alpine" in image.lower() or "arch" in image.lower() or "manjaro" in image.lower():
      helper.error("Degd currently supports Debian and Ubuntu images")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user):
      helper.error(f"invalid container user: {user}")

    self.is_new = False
    self._path = os.path.realpath(binary)
    self._binary = Degd.WORKDIR + "/" + os.path.basename(binary)
    self._image = image
    self._user = user
    self._forward = dict(forward or {})
    self._cap_add = list(cap_add or [])
    self._privileged = privileged
    self._rm = rm
    self._symbols = symbols
    self._packages = list(Degd.DEFAULT_PACKAGES)
    if packages:
      self._packages.extend(packages)
    if symbols:
      helper.warn(f"installing {Pwngd.LIBC6_DEBUG} might update libc binary")
      self._packages.append(Pwngd.LIBC6_DEBUG)

    self._client = docker.from_env()
    self._vm_setup()
    self._container = self._client.containers.get(self._id)

    self._workdir = Degd.WORKDIR
    if tmp:
      result = self._container.exec_run(["mktemp", "-d", "/tmp/vagd.XXXXXXXX"], user="root")
      if result.exit_code:
        helper.error(result.output.decode(errors="replace"))
      self._workdir = result.output.decode().strip()
      self._binary = self._workdir + "/" + os.path.basename(binary)

    if self._sync(self._path):
      self._run_wait(["chmod", "+x", self._binary], user="root")

    if isinstance(files, str):
      self._sync(files)
    elif files:
      for file in files:
        self._sync(file)

    if libs:
      os.makedirs(Pwngd.LIBS_DIRECTORY, exist_ok=True)
      self.libs(Pwngd.LIBS_DIRECTORY)

  def _ssh_setup(self) -> None:
    pass

  def _configuration(self) -> Dict[str, Any]:
    configuration = self._image_configuration()
    configuration.update(
      {
        "cap_add": self._cap_add,
        "privileged": self._privileged,
      }
    )
    return configuration

  def _image_configuration(self) -> Dict[str, Any]:
    return {
      "image": self._image,
      "packages": self._packages,
      "symbols": self._symbols,
      "user": self._user,
    }

  def _build_directory(self) -> str:
    digest = hashlib.sha256(
      json.dumps(self._image_configuration(), sort_keys=True).encode()
    ).hexdigest()[:16]
    return os.path.join(Degd.DOCKERHOME, digest)

  def _create_dockerfile(self) -> str:
    directory = self._build_directory()
    os.makedirs(directory, exist_ok=True)
    dockerfile = os.path.join(directory, "Dockerfile")
    with open(dockerfile, "w") as output:
      output.write(
        templates.DOCKER_API_TEMPLATE.format(
          image=self._image,
          lock=templates.LOCK_PACKAGES if self._symbols else "",
          packages=" ".join(self._packages),
          user=self._user,
        )
      )
    return dockerfile

  def _build_image(self) -> Any:
    dockerfile = self._create_dockerfile()
    tag = "vagd/degd-" + os.path.basename(self._build_directory())
    progress = helper.progress("building native Docker image")
    image = self._client.images.build(
      path=os.path.dirname(dockerfile), dockerfile=dockerfile, tag=tag
    )[0]
    progress.success("done")
    return image

  def _container_name(self) -> str:
    binary = re.sub(r"[^a-zA-Z0-9_.-]", "-", os.path.basename(self._path))
    return "vagd-api-" + binary

  def _create_container(self) -> None:
    self._lock(Degd.TYPE)
    self.is_new = True
    image = self._build_image()
    self._gdb_port = helper.first_free_port(Degd.GDBSERVER_PORT)
    ports = dict(self._forward)
    ports[f"{Degd.GDBSERVER_PORT}/tcp"] = ("127.0.0.1", self._gdb_port)

    resource = os.path.join(os.path.dirname(os.path.dirname(__file__)), "res", "seccomp.json")
    with open(resource, "r") as seccomp_file:
      seccomp_rules = seccomp_file.read().strip()

    container = self._client.containers.run(
      image,
      name=self._container_name(),
      command=["sleep", "infinity"],
      ports=ports,
      detach=True,
      remove=self._rm,
      cap_add=self._cap_add,
      privileged=self._privileged,
      security_opt=[f"seccomp:{seccomp_rules}"],
      labels={"vagd.type": Degd.TYPE},
    )
    self._id = container.id
    state = {
      "configuration": self._configuration(),
      "gdb_port": self._gdb_port,
      "id": self._id,
    }
    with open(Degd.LOCKFILE, "w") as lockfile:
      json.dump(state, lockfile)
    helper.info(f"started native Docker instance {container.short_id}")

  def _vm_setup(self) -> None:
    if not os.path.exists(Degd.LOCKFILE):
      self._create_container()
      return

    with open(Degd.LOCKFILE, "r") as lockfile:
      state = json.load(lockfile)
    try:
      container = self._client.containers.get(state["id"])
    except docker.errors.NotFound:
      self._create_container()
      return

    if container.status != "running":
      container.remove(force=True)
      self._create_container()
      return
    if state.get("configuration") != self._configuration():
      helper.error("running Degd instance has different settings; run 'vagd clean' first")

    self._lock(Degd.TYPE)
    self._id = state["id"]
    self._gdb_port = state["gdb_port"]
    helper.info(f"using native Docker instance {container.short_id}")

  def _run_wait(self, command: Union[str, List[str]], user: Optional[str] = None) -> bytes:
    result = self._container.exec_run(
      command,
      user=user or self._user,
      workdir=self._workdir,
    )
    if result.exit_code:
      helper.error(result.output.decode(errors="replace"))
    return result.output

  def _remote_exists(self, path: str) -> bool:
    result = self._container.exec_run(["test", "-e", path], user=self._user)
    return result.exit_code == 0

  def _sync(self, file: str) -> bool:
    remote = self._workdir + "/" + os.path.basename(file.rstrip("/"))
    if self._remote_exists(remote):
      return False
    self.put(file, self._workdir)
    return True

  @staticmethod
  def _archive(path: str) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
      archive.add(path, arcname=os.path.basename(path.rstrip("/")))
    return data.getvalue()

  @staticmethod
  def put_to(container: Any, file: str, remote: str) -> None:
    if not container.put_archive(remote, Degd._archive(file)):
      helper.error(f"failed to upload {file} to {remote}")

  def put(self, file: str, remote: Optional[str] = None) -> None:
    destination = remote or self._workdir
    Degd.put_to(self._container, file, destination)

  @staticmethod
  def pull_from(container: Any, file: str, local: Optional[str] = None) -> None:
    chunks, stat = container.get_archive(file)
    data = io.BytesIO(b"".join(chunks))
    with tarfile.open(fileobj=data, mode="r:*") as archive:
      members = archive.getmembers()
      if not members:
        helper.error(f"empty archive returned for {file}")
      if stat.get("mode", 0) & 0o170000 == 0o040000:
        destination = local or "."
        archive.extractall(destination)
      else:
        member = members[0]
        destination = local or os.path.basename(file)
        if os.path.isdir(destination):
          destination = os.path.join(destination, os.path.basename(file))
        source = archive.extractfile(member)
        if source is None:
          helper.error(f"failed to extract {file}")
        with open(destination, "wb") as output:
          output.write(source.read())

  def pull(self, file: str, local: Optional[str] = None) -> None:
    try:
      Degd.pull_from(self._container, file, local)
    except docker.errors.NotFound:
      helper.error(f"failed to download {file}")

  def libs(self, directory: str) -> None:
    output = self._run_wait(["ldd", self._binary]).decode(errors="replace")
    libraries = set(re.findall(r"(?:=>\s+)?(/[^\s]+)", output))
    for library in libraries:
      self.pull(library, os.path.join(directory, os.path.basename(library)))

  def which(self, program: str) -> Optional[str]:
    result = self._container.exec_run(
      ["sh", "-lc", f"command -v -- {shlex.quote(program)}"], user=self._user
    )
    if result.exit_code:
      return None
    return result.output.decode().strip()

  def process(
    self,
    argv: Optional[List[str]] = None,
    command: Optional[List[str]] = None,
    **kwargs: Any,
  ) -> DockerExecTube:
    argv = argv or []
    command = command or [self._binary] + argv
    command = [os.fsdecode(argument) for argument in command]
    env = kwargs.pop("env", kwargs.pop("environment", None))
    if isinstance(env, dict):
      env = {os.fsdecode(key): os.fsdecode(value) for key, value in env.items()}
    cwd = kwargs.pop("cwd", kwargs.pop("workdir", self._workdir))
    user = kwargs.pop("user", self._user)
    timeout = kwargs.pop("timeout", DockerExecTube.default)
    level = kwargs.pop("level", None)
    if kwargs:
      helper.error(f"unsupported Docker process arguments: {', '.join(kwargs)}")

    exec_id = self._client.api.exec_create(
      self._id,
      command,
      stdin=True,
      stdout=True,
      stderr=True,
      tty=False,
      user=user,
      environment=env,
      workdir=cwd,
    )["Id"]
    stream = self._client.api.exec_start(exec_id, socket=True, tty=False)
    target = DockerExecTube(
      self._client.api,
      exec_id,
      stream,
      tty=False,
      timeout=timeout,
      level=level,
    )
    target.executable = command[0]
    return target

  def system(self, command: Union[str, List[str]]) -> DockerExecTube:
    if isinstance(command, str):
      command = ["sh", "-lc", command]
    return self.process(command=command)

  def debug(
    self,
    argv: Optional[List[str]] = None,
    gdb_args: Optional[List[str]] = None,
    gdbscript: str = "",
    sysroot: Optional[str] = None,
    sysroot_debug: Optional[str] = None,
    api: bool = False,
    **kwargs: Any,
  ) -> DockerExecTube:
    argv = argv or []
    if sysroot_debug:
      gdbscript = f"set debug-file-directory {sysroot_debug}\n" + gdbscript
    command = [
      "gdbserver",
      f"0.0.0.0:{Degd.GDBSERVER_PORT}",
      self._binary,
      *argv,
    ]
    target = self.process(command=command, **kwargs)
    target.recvline_contains(b"Listening on port", timeout=10)
    attached = pwnlib.gdb.attach(
      ("127.0.0.1", self._gdb_port),
      exe=self._path,
      gdbscript=gdbscript,
      gdb_args=gdb_args,
      sysroot=sysroot,
      api=api,
    )
    if api:
      target.gdb_pid, target.gdb = attached
    else:
      target.gdb_pid = attached
    return target

  def start(
    self,
    argv: Optional[List[str]] = None,
    gdbscript: str = "",
    api: bool = False,
    sysroot: Optional[str] = None,
    sysroot_debug: Optional[str] = None,
    gdb_args: Optional[List[str]] = None,
    **kwargs: Any,
  ) -> DockerExecTube:
    if pwnlib.args.args.GDB:
      return self.debug(
        argv=argv,
        gdbscript=gdbscript,
        api=api,
        sysroot=sysroot,
        sysroot_debug=sysroot_debug,
        gdb_args=gdb_args,
        **kwargs,
      )
    return self.process(argv=argv, **kwargs)
