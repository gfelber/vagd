import errno
import select
import socket
import struct
import time
from typing import Any, Optional

from pwnlib.tubes.tube import tube


class DockerExecTube(tube):
  """Pwntools tube backed by an attached Docker exec socket."""

  _HEADER_SIZE = 8

  def __init__(
    self,
    api: Any,
    exec_id: str,
    stream: Any,
    tty: bool = False,
    timeout: Any = tube.default,
    level: Optional[str] = None,
  ):
    self._api = api
    self.exec_id = exec_id
    self._stream = stream
    self.sock = getattr(stream, "_sock", stream)
    self.tty = tty
    self.closed = {"recv": False, "send": False}
    self._wire_buffer = bytearray()
    self._output_buffer = bytearray()
    super().__init__(timeout=timeout, level=level)

  def _decode_frames(self) -> None:
    if self.tty:
      if self._wire_buffer:
        self._output_buffer.extend(self._wire_buffer)
        self._wire_buffer.clear()
      return

    while len(self._wire_buffer) >= self._HEADER_SIZE:
      stream_type, payload_size = struct.unpack(">BxxxL", self._wire_buffer[: self._HEADER_SIZE])
      frame_size = self._HEADER_SIZE + payload_size
      if stream_type not in (0, 1, 2):
        # Some Docker-compatible engines return an already-demultiplexed socket.
        self._output_buffer.extend(self._wire_buffer)
        self._wire_buffer.clear()
        return
      if len(self._wire_buffer) < frame_size:
        return
      self._output_buffer.extend(self._wire_buffer[self._HEADER_SIZE : frame_size])
      del self._wire_buffer[:frame_size]

  def recv_raw(self, numb: int) -> Optional[bytes]:
    if self.closed["recv"]:
      raise EOFError

    while not self._output_buffer:
      try:
        data = self.sock.recv(max(numb, 4096))
      except socket.timeout:
        return None
      except OSError as error:
        if error.errno in (errno.EAGAIN, errno.ETIMEDOUT):
          return None
        if error.errno in (errno.ECONNRESET, errno.ENOTCONN):
          self.closed["recv"] = True
          raise EOFError
        if error.errno == errno.EINTR:
          continue
        raise

      if not data:
        self.closed["recv"] = True
        raise EOFError

      self._wire_buffer.extend(data)
      self._decode_frames()

    data = bytes(self._output_buffer[:numb])
    del self._output_buffer[:numb]
    return data

  def send_raw(self, data: bytes) -> None:
    if self.closed["send"]:
      raise EOFError
    try:
      self.sock.sendall(data)
    except OSError as error:
      if error.errno in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN):
        self.closed["send"] = True
        raise EOFError
      raise

  def can_recv_raw(self, timeout: float) -> bool:
    if self.closed["recv"]:
      return False
    if self._output_buffer:
      return True
    readable, _, _ = select.select([self.sock], [], [], timeout)
    return bool(readable)

  def connected_raw(self, direction: str) -> bool:
    if direction == "any":
      return not all(self.closed.values())
    return not self.closed[direction]

  def settimeout_raw(self, timeout: Optional[float]) -> None:
    self.sock.settimeout(timeout)

  def shutdown_raw(self, direction: str) -> None:
    if self.closed[direction]:
      return
    self.closed[direction] = True
    how = socket.SHUT_WR if direction == "send" else socket.SHUT_RD
    try:
      self.sock.shutdown(how)
    except OSError as error:
      if error.errno not in (errno.ENOTCONN, errno.EBADF):
        raise

  def close(self) -> None:
    if all(self.closed.values()):
      return
    self.closed["recv"] = True
    self.closed["send"] = True
    try:
      response = getattr(self._stream, "_response", None)
      if response is not None:
        response.close()
      else:
        self._stream.close()
    finally:
      self.sock = None

  def fileno(self) -> int:
    if self.sock is None:
      raise EOFError
    return self.sock.fileno()

  def poll(self, block: bool = False) -> Optional[int]:
    while True:
      info = self._api.exec_inspect(self.exec_id)
      if not info["Running"]:
        return info["ExitCode"]
      if not block:
        return None
      time.sleep(0.05)

  @property
  def pid(self) -> int:
    return self._api.exec_inspect(self.exec_id).get("Pid", 0)
