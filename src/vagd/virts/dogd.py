import os
from typing import Any

import docker

from vagd.virts.pwngd import Pwngd
from vagd.virts.cogd import Cogd


class Dogd(Cogd):
  """
  | Docker virtualization for pwntools

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

  TYPE = "dogd"
  DOCKERHOME = Pwngd.HOME_DIR + "docker/"
  LOCKFILE = Pwngd.LOCAL_DIR + "docker.lock"

  def __init__(
    self,
    binary: str,
    **kwargs: Any,
  ):
    super().__init__(
      binary=binary,
      containerhome=Dogd.DOCKERHOME,
      lockfile=Dogd.LOCKFILE,
      cogd_type=Dogd.TYPE,
      **kwargs,
    )

  def _client_setup(self) -> Any:
    return docker.from_env()
