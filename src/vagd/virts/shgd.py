import pwn
from vagd.virts.pwngd import Pwngd
class Shgd(Pwngd):
    """ ssh interface for pwntools """

    DEFAULT_HOST = 'localhost'
    DEFAULT_PORT = 22
    DEFAULT_USER = 'root'

    _user: str
    _host: str
    _port: int
    _keyfile: str

    def _vm_setup(self) -> None:
        """
        pass
        """
        pass

    def _ssh_setup(self) -> None:
        """
        setups ssh connection to remote
        """
        self._ssh = pwn.ssh(
            user=self._user,
            host=self._host,
            port=self._port,
            keyfile=self._keyfile,
            ignore_config=True
        )

    def __init__(self,
                 binary: str,
                 user: str = DEFAULT_USER,
                 host: str = DEFAULT_HOST,
                 port: int = DEFAULT_PORT,
                 keyfile: str = Pwngd.KEYFILE,
                 **kwargs):
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


