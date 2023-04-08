import os
import pwn
from vagd.virts.pwngd import Pwngd

_GENERATE_KEYPAIR = 'ssh-keygen -q -t ed25519 -f {keyfile} -N ""'


def generate_keypair():
    """
    generate a keypair in .vagd directory
    """
    if not (os.path.exists(Pwngd.KEYFILE) and os.path.exists(Pwngd.KEYFILE + '.pub')):
        pwn.log.info("No Keypair was found. Generating new keypair")
        os.system(_GENERATE_KEYPAIR.format(keyfile=Pwngd.KEYFILE))


def is_port_in_use(port: int) -> bool:
    """
    check if a port is currently used
    :param port: port to check
    :return: if the port is already used
    """
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0


def first_free_port(start: int = 2222, tries: int = 101) -> int:
    """
    returns first free port starting from start (max increments = tries)
    :param start: start of port search
    :param tries: number of tries to increment ports
    :return: first free port
    """
    for i in range(tries):
        port = start + i
        if not is_port_in_use(port):
            return port

    pwn.log.error(f'No free port inside range {start}-{start+tries}')
