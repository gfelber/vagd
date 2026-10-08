import os
import re
from typing import Dict, Optional, Tuple

_FROM = re.compile(
  r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE | re.MULTILINE
)
_ARG = re.compile(r"^\s*ARG\s+(\w+)=(\S+)", re.IGNORECASE | re.MULTILINE)
_VAR = re.compile(r"\$\{(\w+)(?::-([^}]*))?\}|\$(\w+)")

# compiler strings like "GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
_UBUNTU_RELEASE = re.compile(r"ubuntu[^)\s]*~(\d\d\.\d\d)", re.IGNORECASE)
_COMPILER = re.compile(r"GCC: \((Ubuntu|Debian)[^)]*\) (\d+)")
# default compiler of a release, used when the package version has no ~XX.YY suffix
_UBUNTU_GCC = {4: "14.04", 5: "16.04", 7: "18.04", 9: "20.04", 11: "22.04", 13: "24.04", 14: "25.04", 15: "25.10"}
_DEBIAN_GCC = {6: "9", 8: "10", 10: "11", 12: "12", 14: "13"}


def image_from_dockerfile(path: str) -> Optional[str]:
  """Return the base image of the final stage of a Dockerfile."""
  with open(path) as dockerfile:
    content = re.sub(r"\\\r?\n", " ", dockerfile.read())

  args: Dict[str, str] = {m.group(1): m.group(2).strip("\"'") for m in _ARG.finditer(content)}

  def substitute(match: re.Match) -> str:
    name = match.group(1) or match.group(3)
    return args.get(name, match.group(2) if match.group(2) is not None else match.group(0))

  stages: Dict[str, str] = dict()
  image = None
  for match in _FROM.finditer(content):
    image = _VAR.sub(substitute, match.group(1))
    image = stages.get(image, image)
    if match.group(2):
      stages[match.group(2)] = image

  if image is None or "$" in image or image == "scratch":
    return None
  return image


def image_from_comment(binary: str) -> Optional[str]:
  """Guess the distribution image from the compiler string in .comment."""
  from pwnlib.elf.elf import ELF

  elf = ELF(binary, checksec=False)
  if elf.get_section_by_name(".comment") is None:
    return None
  comment = elf.section(".comment").replace(b"\0", b" ").decode(errors="replace")

  release = _UBUNTU_RELEASE.search(comment)
  if release:
    return f"ubuntu:{release.group(1)}"

  match = _COMPILER.search(comment)
  if match is None:
    return None
  distro, major = match.group(1).lower(), int(match.group(2))
  if distro == "ubuntu" and major in _UBUNTU_GCC:
    return f"ubuntu:{_UBUNTU_GCC[major]}"
  if distro == "debian" and major in _DEBIAN_GCC:
    return f"debian:{_DEBIAN_GCC[major]}"
  return None


def detect_image(binary: str) -> Tuple[str, str]:
  """
  Detect the container image for a binary.

  Checks a Dockerfile next to the binary (then in the working directory) and
  falls back to the compiler string in the binary's .comment section.

  :return: tuple of image and the source it was detected from
  :raises ValueError: if no image could be detected
  """
  candidates = [os.path.join(os.path.dirname(binary) or ".", "Dockerfile"), "Dockerfile"]
  for dockerfile in candidates:
    if os.path.isfile(dockerfile):
      image = image_from_dockerfile(dockerfile)
      if image is None:
        raise ValueError(f"could not resolve the final FROM in {dockerfile}")
      return image, dockerfile

  if not os.path.isfile(binary):
    raise ValueError("no Dockerfile found and no binary supplied")
  image = image_from_comment(binary)
  if image is None:
    raise ValueError("no Dockerfile found and .comment has no known Ubuntu/Debian compiler string")
  return image, ".comment"
