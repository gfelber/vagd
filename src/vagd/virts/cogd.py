import os
from typing import Any, Dict, List, Optional
from abc import abstractmethod

import docker
import podman

from vagd import helper, templates
from vagd.box import Box
from vagd.virts.pwngd import Pwngd
from vagd.virts.shgd import Shgd


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
  :param symbols: additionally install libc6 debug symbols (also updates libc6)
  :param ex: if experimental features, e.g. alpine, gdbserver should be enabled
  :param rm: remove container after exit
  :param alpine: if the conainter is alpine (also autochecks image name)
  :param fast: mounts libs locally for faster symbol extraction (experimental) NOT COMPATIBLE WITH ALPINE
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
  _template: str
  _containerhome: str
  _lockfile: str
  _type: str

  VAGD_PREFIX = "vagd-"
  DEFAULT_USER = "vagd"
  DEFAULT_PORT = 2222
  DEFAULT_IMAGE = Box.DOCKER_NOBLE

  DEFAULT_PACKAGES = Pwngd.DEFAULT_PACKAGES + ["openssh-server"]

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
    symbols: bool = True,
    rm: bool = True,
    ex: bool = False,
    fast: bool = False,
    alpine: bool = False,
    **kwargs: Any,
  ):
    self._image = image
    self._name = Cogd.VAGD_PREFIX + os.path.basename(binary)
    self._packages = list(Cogd.DEFAULT_PACKAGES)
    self._containerhome = containerhome
    self._lockfile = lockfile
    self._type = cogd_type

    if symbols:
      helper.warn(f"installing {Pwngd.LIBC6_DEBUG} might update libc binary, consider using symbols=False")
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
          keyfile=os.path.basename(self._containerdir + "keyfile.pub"),
        )
      )

  def _create_container_instance(self):
    self.is_new = True
    helper.info("starting container instance")
    self._port = helper.first_free_port(Cogd.DEFAULT_PORT)
    self._forward.update({"22/tcp": self._port})

    dir = os.path.dirname(os.path.realpath(__file__))
    with open(dir[: dir.rfind("/")] + "/res/seccomp.json", "r") as seccomp_file:
      seccomp_rules = seccomp_file.read().strip()

    container = self._client.containers.run(
      self._bimage,
      name=self._name,
      ports=self._forward,
      detach=True,
      remove=self._rm,
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
