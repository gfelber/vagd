import os
from typing import Dict, List

import docker

from vagd import helper, templates
from vagd.box import Box
from vagd.virts.pwngd import Pwngd
from vagd.virts.shgd import Shgd


class Dogd(Shgd):
  """
  | Docker virtualization for pwntools

  :param binary: binary to execute
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

  | SSH from cmd

  .. code-block:: bash

      vagd ssh
      # or
      ssh -o "StrictHostKeyChecking=no" -i ~/.share/local/vagd/keyfile -p $(cut .vagd/docker.lock -d":" -f 2) vagd@0.0.0.0

  | connect with docker exec

  .. code-block:: bash

     docker exec -it $(cut ./.vagd/docker.lock -d":" -f 1) /bin/bash

  | Kill from cmd:

  .. code-block:: bash

      vagd clean
      #or
      docker kill $(cut ./.vagd/docker.lock -d":" -f 1)

  | Docker containers are automatically removed after they stop
  | Docker images need to be manually removed from docker
  | Dockerfiles are stored in home directory to allow caching ~/.share/local/vagd/docker/<image>/Dockerfile

  .. code-block:: bash

      docker images # list images
      docker rmi <id> # remove correct image
  """

  _image: str
  _name: str
  _user: str
  _port: int
  _packages: List[str]
  _client: docker.client
  _id: str
  _dockerdir: str
  _dockerfile: str
  _isalpine: bool
  _gdbsrvport: int
  _rm: bool
  _ex: bool
  _forward: Dict[str, int]
  _symbols: bool

  VAGD_PREFIX = "vagd-"
  TYPE = "dogd"
  DOCKERHOME = Pwngd.HOME_DIR + "docker/"
  DEFAULT_USER = "vagd"
  DEFAULT_PORT = 2222
  DEFAULT_IMAGE = Box.DOCKER_NOBLE

  DEFAULT_PACKAGES = Pwngd.DEFAULT_PACKAGES + ["openssh-server"]
  LOCKFILE = Pwngd.LOCAL_DIR + "docker.lock"

  def __init__(
    self,
    binary: str,
    image: str = DEFAULT_IMAGE,
    user: str = DEFAULT_USER,
    forward: Dict[str, int] = None,
    packages: List[str] = None,
    symbols=True,
    rm=True,
    ex: bool = False,
    fast: bool = False,
    alpine: bool = False,
    **kwargs,
  ):
    self._image = image
    self._name = Dogd.VAGD_PREFIX + os.path.basename(binary)
    self._packages = list(Dogd.DEFAULT_PACKAGES)

    if symbols:
      helper.warn(
        f"installing {Pwngd.LIBC6_DEBUG} might update libc binary, consider using symbols=False"
      )
      self._packages.append(Pwngd.LIBC6_DEBUG)

    self._isalpine = alpine or "alpine" in image

    if packages is not None:
      if self._isalpine:
        helper.error("additional package installation not supported for alpine")
    else:
      # trigger package detection in Pwngdb
      packages = list()

    self._gdbsrvport = -1
    self._dockerdir = Dogd.DOCKERHOME + f"{self._image}/"
    if not (
      os.path.exists(Dogd.DOCKERHOME) and os.path.exists(self._dockerdir)
    ):
      os.makedirs(self._dockerdir)
    self._dockerfile = self._dockerdir + "Dockerfile"
    self._user = user
    self._forward = forward
    self._rm = rm
    self._ex = ex
    self._symbols = symbols
    if self._isalpine and not self._ex:
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
      gdbsrvport=self._gdbsrvport,
      **kwargs,
    )

  def _create_dockerfile(self):
    helper.info(f"create new Dockerfile at {self._dockerfile}")
    if not os.path.exists(Pwngd.KEYFILE):
      helper.generate_keypair()

    if not os.path.exists(self._dockerdir + "keyfile.pub"):
      os.link(Pwngd.PUBKEYFILE, self._dockerdir + "keyfile.pub")
    template = (
      templates.DOCKER_ALPINE_TEMPLATE
      if self._isalpine
      else templates.DOCKER_TEMPLATE
    )

    with open(self._dockerfile, "w") as dockerfile:
      dockerfile.write(
        template.format(
          image=self._image,
          packages=" ".join(self._packages),
          user=self._user if self._user != "root" else Dogd.DEFAULT_USER,
          keyfile=os.path.basename(self._dockerdir + "keyfile.pub"),
        )
      )

  def _create_docker_instance(self):
    self.is_new = True
    helper.info("starting docker instance")
    self._port = helper.first_free_port(Dogd.DEFAULT_PORT)
    self._forward.update({"22/tcp": self._port})
    if self._isalpine:
      self._gdbsrvport = helper.first_free_port(Pwngd.STATIC_GDBSRV_PORT)
      self._forward.update({f"{self._gdbsrvport}/tcp": self._gdbsrvport})

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
    helper.info(f"started docker instance {container.short_id}")
    with open(Dogd.LOCKFILE, "w") as lockfile:
      lockfile.write(
        f"{container.id}:{str(self._port)}:{str(self._gdbsrvport)}"
      )

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
      path=os.path.dirname(self._dockerfile), tag=f"vagd/{tag}"
    )[0]

    build_progress.success("done")

    return bimage

  def _vm_create(self):
    self._lock(Dogd.TYPE)

    if not os.path.exists(Pwngd.LOCAL_DIR):
      os.makedirs(Pwngd.LOCAL_DIR)

    # enfore changes to Dockerfile are always rebuild by docker
    self._create_dockerfile()

    self._bimage = self._build_image()

    self._create_docker_instance()

  def _vm_setup(self) -> None:
    self._client = docker.from_env()
    if not os.path.exists(Dogd.LOCKFILE):
      helper.info(
        f"No Lockfile {Dogd.LOCKFILE} found, creating new Docker Instance"
      )
      self._vm_create()
    else:
      with open(Dogd.LOCKFILE, "r") as lockfile:
        data = lockfile.readline().split(":")
        self._id = data[0]
        self._port = int(data[1])
        if self._isalpine:
          self._gdbsrvport = int(data[2])
      if not self._client.containers.list(filters={"id": self._id}):
        helper.info(
          f"Lockfile {Dogd.LOCKFILE} found, container not running, creating new one"
        )
        self._vm_create()
      else:
        helper.info(
          f"Lockfile {Dogd.LOCKFILE} found, Docker Instance f{self._client.containers.get(self._id).short_id}"
        )
