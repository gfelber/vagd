import os
from typing import Any

import podman

from vagd import helper
from vagd.virts.pwngd import Pwngd
from vagd.virts.cogd import Cogd


class Pogd(Cogd):
  """
  | Podman virtualization for pwntools

  :param kwargs: parameters to pass through to super

  | SSH from cmd

  .. code-block:: bash

      vagd ssh
      # or
      ssh -o "StrictHostKeyChecking=no" -i ~/.share/local/vagd/keyfile -p $(cut .vagd/podman.lock -d":" -f 2) vagd@0.0.0.0

  | connect with podman exec

  .. code-block:: bash

     podman exec -it $(cut ./.vagd/podman.lock -d":" -f 1) /bin/bash

  | Kill from cmd:

  .. code-block:: bash

      vagd clean
      #or
      podman kill $(cut ./.vagd/podman.lock -d":" -f 1)

  | Podman containers are automatically removed after they stop
  | Podman images need to be manually removed from docker
  | Dockerfiles are stored in home directory to allow caching ~/.share/local/vagd/podman/<image>/Dockerfile

  .. code-block:: bash

      podman images # list images
      podman rmi <id> # remove correct image
  """

  TYPE = "pogd"
  PODMANHOME = Pwngd.HOME_DIR + "podman/"
  LOCKFILE = Pwngd.LOCAL_DIR + "podman.lock"

  def __init__(
    self,
    binary: str,
    **kwargs: Any,
  ):
    super().__init__(
      binary=binary,
      containerhome=Pogd.PODMANHOME,
      lockfile=Pogd.LOCKFILE,
      cogd_type=Pogd.TYPE,
      **kwargs,
    )

  def _client_setup(self) -> Any:
    # check if podman rest api service is running
    uid = os.getuid()
    run_dir = f"/run/user/{uid}"
    podman_dir = os.path.join(run_dir, "podman")
    sock_path = os.path.join(podman_dir, "podman.sock")

    if not os.path.exists(sock_path):
      helper.error("Podman system  API service not running. Use: podman system servic --time=0")
      return

    return podman.from_env()
