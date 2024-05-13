import pwn
from typing import Iterable
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
        pwn.log.error("NOT IMPLEMENTED")
    def _ssh_setup(self) -> None:
        """
        NOT IMPLEMENTED
        """
        pwn.log.error("NOT IMPLEMENTED")

    def __init__(self,
                 binary: str,
                 **kwargs):
        """
        :param binary: binary to execute
        """
        self._binary = binary
    def _sync(self, file: str) -> None:
        """
        NOT IMPLEMENTED
        """
        pwn.log.error("NOT IMPLEMENTED")

    def _mount(self, remote_dir: str, local_dir: str) -> None:
        """
        NOT IMPLEMENTED
        """
        pwn.log.error("NOT IMPLEMENTED")

    def _mount_lib(self, remote_lib: str = '/usr/lib') -> None:
        """
        NOT IMPLEMENTED
        """
        pwn.log.error("NOT IMPLEMENTED")

    def system(self, cmd: str) -> pwn.tubes.ssh.ssh_channel:
        """
        NOT IMPLEMENTED
        """
        pwn.log.error("NOT IMPLEMENTED")

    def _install_packages(self, packages: Iterable):
        """
        NOT IMPLEMENTED
        """
        pwn.log.error("NOT IMPLEMENTED")

    def put(self, file: str, remote: str = None):
        """
        NOT IMPLEMENTED
        """
        pwn.log.error("NOT IMPLEMENTED")

    def debug(self, **kwargs) -> pwn.process:
        """
        run binary with gdb locally
        :param kwargs: pwntool arguments
        :rtype: pwn.process
        """
        return self.pwn_debug(**kwargs)

    def pwn_debug(self, argv: list[str] = None, **kwargs) -> pwn.process:
        """
        run binary with gdb locally
        :param argv: comandline arguments for binary
        :param kwargs: pwntool arguments
        :rtype: pwn.process
        """
        return pwn.gdb.debug([self._binary] + argv, **kwargs)

    def process(self, argv: list[str] = None, **kwargs) -> pwn.process:
        """
        run binary locally
        :param argv: comandline arguments for binary
        :param kwargs: pwntool parameters
        :return: pwntools process
        """
        return pwn.process([self._binary] + argv, **kwargs)

    def start(self,
              argv: list[str] = None,
              gdbscript: str = '',
              api: bool = None,
              **kwargs) -> pwn.process:
        """
        start binary locally and return pwn.process
        :param argv: commandline arguments for binary
        :param gdbscript: GDB script for GDB
        :param api: if GDB API should be enabled (experimental)
        :param kwargs: pwntool parameters
        :return: pwntools process, if api=True tuple with gdb api
        """
        self._init()
        if pwn.args.GDB:
            return self.pwn_debug(argv=argv, gdbscript=gdbscript, api=api, **kwargs)
        else:
            return self.process(argv=argv, **kwargs)
