import os
import re
import time

import pwnlib.timeout
import pwnlib.tubes.ssh
from typing import Any

from vagd import helper
from vagd.virts.pwngd import Pwngd


class _SocketSSH:
  """Run SSH processes behind a one-shot TCP listener."""

  _LISTEN = "TCP4-LISTEN:0,bind=127.0.0.1"
  _PORT = re.compile(rb"listening on .*:(\d+)\s*$")

  def __init__(self, ssh: pwnlib.tubes.ssh.ssh):
    self._ssh = ssh

  def __getattr__(self, name: str) -> Any:
    return getattr(self._ssh, name)

  def connect_remote(self, *args: Any, **kwargs: Any) -> pwnlib.tubes.sock.sock:
    """Connect through SSH without leaking Paramiko teardown races."""
    tube = self._ssh.connect_remote(*args, **kwargs)
    shutdown_raw = tube.shutdown_raw

    def safe_shutdown_raw(direction: str) -> None:
      try:
        shutdown_raw(direction)
      except EOFError:
        # The peer and SSH transport can close between connect_both() seeing
        # EOF and forwarding the corresponding half-close. The requested
        # direction is already marked closed by pwntools at this point.
        pass

    tube.shutdown_raw = safe_shutdown_raw
    return tube

  def process(self, argv: Any = None, **kwargs: Any) -> pwnlib.tubes.sock.sock:
    """
    Create the process with pwntools' execve wrapper, then let socat run it.

    The listener intentionally has neither a fixed port nor socat's listener
    ``fork`` option. It accepts exactly one connection and terminates its child
    when that connection closes.
    """
    timeout = kwargs.get("timeout", pwnlib.timeout.Timeout.default)
    wrapper = os.fsdecode(self._ssh.process(argv, run=False, **kwargs))
    python = self._ssh.which("python3")
    socat_path = self._ssh.which("socat")
    if not python:
      helper.error("python3 isn't installed on the remote system")
    if not socat_path:
      helper.error("socat isn't installed on the remote system")

    socat = self._ssh.process(
      [
        os.fsdecode(socat_path),
        "-d",
        "-d",
        self._LISTEN,
        f"EXEC:{os.fsdecode(python)} {wrapper},stderr",
      ],
      tty=False,
      raw=True,
      aslr=True,
    )

    while True:
      try:
        line = socat.recvline(timeout=3)
      except EOFError:
        helper.error("socat exited before opening its listener")
      if not line:
        socat.close()
        helper.error("timed out waiting for socat to open its listener")
      match = self._PORT.search(line)
      if match:
        break

    tube = self._ssh.connect_remote("127.0.0.1", int(match.group(1)), timeout=timeout)
    # Keep the SSH control channel alive until the socket is closed. The
    # one-shot socat process then exits and kills its child automatically.
    tube.socat = socat
    return tube


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
  DEFAULT_PACKAGES = Pwngd.DEFAULT_PACKAGES + ["socat"]

  _user: str
  _host: str
  _port: int
  _keyfile: str
  _ssh: pwnlib.tubes.ssh.ssh

  def _transport(self, socket: bool = False) -> Any:
    if socket:
      return _SocketSSH(self._ssh)
    return self._ssh

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
    **kwargs: Any,
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
