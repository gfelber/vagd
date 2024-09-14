from typing import Iterable

import pwnlib.args
import pwnlib.tubes

from vagd import helper
from vagd.virts.pwngd import Pwngd


class Logd(Pwngd):
  """
  local execution of binary

  :param binary: binary to execute
  """

  _binary: str

  def _vm_setup(self) -> None:
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def _ssh_setup(self) -> None:
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def __init__(self, binary: str, **kwargs):
    """
    :param binary: binary to execute
    """
    self._binary = binary

  def _sync(self, file: str) -> None:
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def _mount(self, remote_dir: str, local_dir: str) -> None:
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def _mount_lib(self, remote_lib: str = "/usr/lib") -> None:
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def system(self, cmd: str) -> None:
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def _install_packages(self, packages: Iterable):
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def put(self, file: str, remote: str = None):
    """
    NOT IMPLEMENTED
    """
    helper.error("NOT IMPLEMENTED")

  def debug(self, **kwargs) -> pwnlib.tubes.process.process:
    """
    run binary with gdb locally
    :param kwargs: pwntool arguments
    :rtype: pwnlib.tubes.process.process
    """
    return self.pwn_debug(**kwargs)

  def pwn_debug(
    self, argv: list[str] = None, **kwargs
  ) -> pwnlib.tubes.process.process:
    """
    run binary with gdb locally
    :param argv: comandline arguments for binary
    :param kwargs: pwntool arguments
    :rtype: pwnlib.tubes.process.process
    """
    return pwnlib.gdb.debug([self._binary] + argv, **kwargs)

  def process(
    self, argv: list[str] = None, **kwargs
  ) -> pwnlib.tubes.process.process:
    """
    run binary locally
    :param argv: comandline arguments for binary
    :param kwargs: pwntool parameters
    :return: pwntools process
    """
    return pwnlib.tubes.process.process([self._binary] + argv, **kwargs)

  def start(
    self,
    argv: list[str] = None,
    gdbscript: str = "",
    api: bool = None,
    **kwargs,
  ) -> pwnlib.tubes.process.process:
    """
    start binary locally and return pwnlib.tubes.process.process
    :param argv: commandline arguments for binary
    :param gdbscript: GDB script for GDB
    :param api: if GDB API should be enabled (experimental)
    :param kwargs: pwntool parameters
    :return: pwntools process, if api=True tuple with gdb api
    """
    helper.warn("running locally, only limited functions are supported")
    if pwnlib.args.args.GDB:
      return self.pwn_debug(argv=argv, gdbscript=gdbscript, api=api, **kwargs)
    else:
      return self.process(argv=argv, **kwargs)
