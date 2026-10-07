import os
import shutil
import stat
import subprocess
import tempfile
from typing import List, Optional, Sequence, Tuple


def _run_patchelf(patchelf: str, *args: str) -> subprocess.CompletedProcess:
  try:
    return subprocess.run(
      [patchelf, *args],
      check=True,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
    )
  except subprocess.CalledProcessError as error:
    message = error.stderr.strip() or error.stdout.strip() or str(error)
    raise RuntimeError(f"patchelf failed: {message}") from error


def _executable(path: str) -> None:
  """Make an ELF artifact readable and executable without removing existing modes."""
  os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) | 0o555)


def _library_name(patchelf: str, library: str) -> str:
  """Use the SONAME when available so DT_NEEDED can find renamed libraries."""
  soname = _run_patchelf(patchelf, "--print-soname", library).stdout.strip()
  return os.path.basename(soname) if soname else os.path.basename(library)


def _same_file(first: str, second: str) -> bool:
  return os.path.exists(second) and os.path.samefile(first, second)


def patch_binary(
  binary: str,
  libraries: Optional[Sequence[str]] = None,
  interpreter: Optional[str] = None,
) -> Tuple[List[str], Optional[str]]:
  """Patch *binary* to use local ELF artifacts and return their staged paths.

  Libraries are copied beside the binary under their SONAME and found through
  ``$ORIGIN``.  The interpreter is encoded as ``./<name>`` so the exact same
  executable works locally and after upload.  The first invocation preserves
  the unmodified executable as ``<binary>.bak``.
  """
  if isinstance(libraries, str):
    libraries = [libraries]
  else:
    libraries = list(libraries or ())
  if not libraries and not interpreter:
    return [], None

  patchelf = shutil.which("patchelf")
  if not patchelf:
    raise RuntimeError("patchelf is required when libraries or an interpreter are supplied")

  binary = os.path.abspath(os.path.expanduser(binary))
  if not os.path.isfile(binary):
    raise FileNotFoundError(binary)

  library_dir = os.path.dirname(binary)
  backup = binary + ".bak"
  staged_libraries = []
  destinations = {}
  for library in libraries:
    source = os.path.abspath(os.path.expanduser(library))
    if not os.path.isfile(source):
      raise FileNotFoundError(source)

    destination = os.path.join(library_dir, _library_name(patchelf, source))
    if destination in (binary, backup):
      raise ValueError("a library name conflicts with the binary or its backup")
    if destination in destinations:
      if os.path.samefile(source, destinations[destination]):
        continue
      raise ValueError(f"multiple libraries resolve to {os.path.basename(destination)!r}")
    destinations[destination] = source

    if not _same_file(source, destination):
      shutil.copy2(source, destination)
    _executable(destination)
    staged_libraries.append(destination)

  staged_interpreter = None
  if interpreter:
    source = os.path.abspath(os.path.expanduser(interpreter))
    if not os.path.isfile(source):
      raise FileNotFoundError(source)
    staged_interpreter = os.path.join(library_dir, os.path.basename(source))
    if staged_interpreter in (binary, backup):
      raise ValueError("the interpreter name conflicts with the binary or its backup")
    if staged_interpreter in destinations and destinations[staged_interpreter] != source:
      raise ValueError("the interpreter name conflicts with a supplied library")
    if not _same_file(source, staged_interpreter):
      shutil.copy2(source, staged_interpreter)
    _executable(staged_interpreter)

  if not os.path.exists(backup):
    shutil.copy2(binary, backup)

  # Patch a temporary copy so a failed patchelf invocation never leaves the
  # user's executable half-modified.
  fd, temporary = tempfile.mkstemp(prefix=".vagd-patchelf-", dir=library_dir)
  os.close(fd)
  try:
    shutil.copy2(binary, temporary)
    args = []
    if staged_libraries:
      current_rpath = _run_patchelf(patchelf, "--print-rpath", temporary).stdout.strip()
      rpath_entries = [entry for entry in current_rpath.split(":") if entry]
      rpath_entries = ["$ORIGIN"] + [entry for entry in rpath_entries if entry != "$ORIGIN"]
      args += ["--force-rpath", "--set-rpath", ":".join(rpath_entries)]
    if staged_interpreter:
      args += ["--set-interpreter", "./" + os.path.basename(staged_interpreter)]
    _run_patchelf(patchelf, *args, temporary)
    _executable(temporary)
    os.replace(temporary, binary)
  finally:
    if os.path.exists(temporary):
      os.unlink(temporary)

  return staged_libraries, staged_interpreter
