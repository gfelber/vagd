import os
import sys

import pwnlib.log

from vagd.virts.pwngd import Pwngd

_GENERATE_KEYPAIR = 'ssh-keygen -q -t ed25519 -f {keyfile} -N ""'
log = pwnlib.log.getLogger(None)
log.setLevel(pwnlib.log.logging.INFO)


def _ensure_log():
  """
  ensure the correct logger is set
  """
  global log
  if "pwn" in sys.modules:
    from pwn import log as pwnlog

    log = pwnlog


def info(info: str):
  """
  log info with pwntools
  :param info: info to log
  """
  _ensure_log()
  log.info(info)


def debug(debug: str):
  """
  log debug with pwntools
  :param debug: debug to log
  """
  _ensure_log()
  log.debug(debug)


def warn(warn: str):
  """
  log warn with pwntools
  :param warn: warn to log
  """
  _ensure_log()
  log.warn(warn)


def error(error: str):
  """
  log error with pwntools
  :param error: error to log
  """
  _ensure_log()
  log.error(error)


def progress(progress: str) -> pwnlib.log.Progress:
  """
  log progress with pwntools
  :param progress: progress to log
  """
  _ensure_log()
  return log.progress(progress)


def generate_keypair():
  """
  generate a keypair in .vagd directory
  """
  if not (
    os.path.exists(Pwngd.KEYFILE) and os.path.exists(Pwngd.KEYFILE + ".pub")
  ):
    info("No Keypair was found. Generating new keypair")
    os.system(_GENERATE_KEYPAIR.format(keyfile=Pwngd.KEYFILE))


def is_port_in_use(port: int) -> bool:
  """
  check if a port is currently used
  :param port: port to check
  :return: if the port is already used
  """
  import socket

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    return s.connect_ex(("localhost", port)) == 0


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

  error(f"No free port inside range {start}-{start + tries}")
