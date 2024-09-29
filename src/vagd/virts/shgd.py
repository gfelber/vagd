import time

import pwnlib.tubes.ssh

from vagd import helper
from vagd.virts.pwngd import Pwngd


class Shgd(Pwngd):
  """
  ssh interface for pwntools

  :param binary: binary to execute
  :param user: ssh user
  :param host: ssh hostname
  :param port: ssh port
  :param keyfile: ssh keyfile (default in .vagd)
  :param kwargs: parameters to pass through to super
  """

  DEFAULT_HOST = "localhost"
  DEFAULT_PORT = 22
  DEFAULT_USER = "root"

  _user: str
  _host: str
  _port: int
  _keyfile: str
  _ssh: pwnlib.tubes.ssh.ssh

  def bind(self, port: int) -> int:
    """
    bind port from ssh connection locally
    :param port:
    :return:
    """

    remote = self._ssh.connect_remote("127.0.0.1", port)
    listener = pwnlib.tubes.listen.listen(0)
    port = listener.lport

    # Disable showing GDB traffic when debugging verbosity is increased
    remote.level = "error"
    listener.level = "error"

    # Hook them up
    remote.connect_both(listener)

    return port

  def _vm_setup(self) -> None:
    """
    pass
    """
    pass

  _TRIES = 3  # three times the charm

  def _ssh_setup(self) -> None:
    """
    setup ssh connection
    """
    progress = helper.progress("connecting to ssh")
    for i in range(Shgd._TRIES):
      try:
        self._ssh = pwnlib.tubes.ssh.ssh(
          user=self._user,
          host=self._host,
          port=self._port,
          keyfile=self._keyfile,
          ignore_config=True,
        )
        progress.success("Done")
        break
      except Exception as e:
        if i + 1 == Shgd._TRIES:
          progress.failure("%s", e)
          helper.error("Failed to connect to ssh")
        else:
          progress.status("Trying again")
        time.sleep(1 if i == 0 else 10)

  def __init__(
    self,
    binary: str,
    user: str = DEFAULT_USER,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    keyfile: str = Pwngd.KEYFILE,
    **kwargs,
  ):
    """

    :param binary: binary to execute
    :param user: ssh user
    :param host: ssh hostname
    :param port: ssh port
    :param keyfile: ssh keyfile (default in .vagd)
    :param kwargs: parameters to pass through to super
    """
    self._user = user
    self._host = host
    self._port = port
    self._keyfile = keyfile

    self._ssh_setup()

    super().__init__(binary=binary, **kwargs)
