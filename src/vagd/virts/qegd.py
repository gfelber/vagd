import os
import time
from shutil import copyfile, which
from typing import Dict, List
from urllib.parse import urlparse
from urllib.request import urlretrieve

import pwnlib

from vagd import helper
from vagd.box import Box
from vagd.virts.pwngd import Pwngd
from vagd.virts.shgd import Shgd


class Qegd(Shgd):
  """
  | QEMU Virtualization for pwntools

  :param binary: binary for VM debugging
  :param img: qemu image to use (requires ssh)
  :param user: user inside qemu image
  :param ports: forwarded ports
  :param packages: packages to install on vm
  :param arm: emulate arm in qemu
  :param qemu: qemu cmd
  :param cpu: value for :code -cpu
  :param memory: value for :code -m
  :param cores: value for :code -smp
  :param machine: value for :code -machine
  :param bios: value for :code -bios
  :param custom: custom qemu arguments
  :param detach: run qemu in new terminal
  :param kwargs: parameters to pass through to super

  | SSH from cmd

  .. code-block:: bash

      vagd ssh
      # or
      ssh -o "StrictHostKeyChecking=no" -i ~/.share/local/vagd/keyfile -p $(cat .vagd/qemu.lock) ubuntu@0.0.0.0

  | Kill from cmd:

  .. code-block:: bash

      vagd clean
      # or
      kill $(pgrep qemu)

  | Qemu images are cached in the home directory: :code:`~/.share/local/vagd/qemu-imgs/`
  |
  | current used images are stored in the local directory: :code:`./.vagd/current.img`
  | These should be deleted automatically, but if a machine gets improperly stopped
  | (shutdown host while vm is running) it might remain and use up space. You can find remaining images with:

  .. code-block:: bash

      find ~/ -name current.img
      rm <path/current.img>

  """

  DEFAULT_IMG = Box.QEMU_NOBLE
  QEMU_DIR = Pwngd.LOCAL_DIR
  IMGS_DIR = Pwngd.HOME_DIR + "qemu-imgs/"
  DEFAULT_USER = "vagd"
  DEFAULT_HOST = "0.0.0.0"
  TYPE = "qegd"
  DEFAULT_PORT = 2222

  DEFAULT_QEMU_CMD = "qemu-system-x86_64"
  DEFAULT_QEMU_ARM_CMD = "qemu-system-aarch64"

  DEFAULT_QEMU_MACHINE_PREFIX = "-machine"
  DEFAULT_QEMU_MACHINE = "accel=kvm,type=q35"
  DEFAULT_QEMU_ARM_MACHINE = "virt"

  DEFAULT_QEMU_CPU_PREFIX = "-cpu"
  DEFAULT_QEMU_CPU = "host"
  DEFAULT_QEMU_ARM_CPU = "cortex-a72"

  DEFAULT_QEMU_CORES_PREFIX = "-smp"
  DEFAULT_QEMU_CORES = "2"

  DEFAULT_QEMU_BIOS_PREFIX = "-bios"
  DEFAULT_QEMU_ARM_BIOS = "/usr/share/edk2/aarch64/QEMU_EFI.fd"

  DEFAULT_QEMU_MEMORY_PREFIX = "-m"
  DEFAULT_QEMU_MEMORY = "2G"

  _img: str
  _local_img: str
  _user: str
  _host: str
  _port: int
  _forward: Dict[str, int]
  _qemu: str
  _cpu: str
  _cores: str
  _memory: str
  _bios: str
  _cores: str
  _machine: str
  _detach: bool

  def __init__(
    self,
    binary: str,
    img: str = DEFAULT_IMG,
    user: str = DEFAULT_USER,
    forward: Dict[str, int] = None,
    packages: List[str] = None,
    arm: bool = False,
    qemu: str = DEFAULT_QEMU_CMD,
    cpu: str = DEFAULT_QEMU_CPU,
    memory: str = DEFAULT_QEMU_MEMORY,
    machine: str = DEFAULT_QEMU_MACHINE,
    cores: str = DEFAULT_QEMU_CORES,
    bios: str = None,
    detach: bool = False,
    custom: str = "",
    **kwargs,
  ):
    if not which(qemu):
      helper.error(qemu + " isn't installed")

    if packages is None:
      packages = list()

    if not os.path.exists(Qegd.QEMU_DIR):
      helper.info(f"Generating {Qegd.QEMU_DIR} dir")
      os.makedirs(Qegd.QEMU_DIR)

    if arm:
      qemu = (
        Qegd.DEFAULT_QEMU_ARM_CMD if qemu == Qegd.DEFAULT_QEMU_CMD else qemu
      )
      cpu = Qegd.DEFAULT_QEMU_ARM_CPU if cpu == Qegd.DEFAULT_QEMU_CPU else cpu
      machine = (
        Qegd.DEFAULT_QEMU_ARM_MACHINE
        if machine == Qegd.DEFAULT_QEMU_MACHINE
        else machine
      )
      bios = Qegd.DEFAULT_QEMU_ARM_BIOS if bios is None else bios

    self._img = img
    self._user = user
    self._forward = forward if forward else dict()
    self._qemu = qemu
    self._cpu = cpu
    self._memory = memory
    self._cores = cores
    self._machine = machine
    self._bios = bios
    self._custom = custom
    self._detach = detach

    self._vm_setup()

    packages += Pwngd.DEFAULT_PACKAGES

    super().__init__(
      binary=binary,
      user=user,
      host=self._host,
      port=self._port,
      packages=packages,
      **kwargs,
    )

  @staticmethod
  def _is_local(url) -> bool:
    """
    check if provided url is local or remote
    :param url: url to check
    :return: if the url is local or remote
    """
    url_parsed = urlparse(url)
    if url_parsed.scheme in ("file", ""):  # Possibly a local file
      return os.path.exists(url_parsed.path)
    return False

  CURRENT_IMG = QEMU_DIR + "current.img"

  def _set_local_img(self):
    """
    get local image for qemu machine
    """
    if Qegd._is_local(self._img):
      helper.info("Using local image")
      self._local_img = self._img
    else:
      if not os.path.exists(Qegd.IMGS_DIR):
        os.makedirs(Qegd.IMGS_DIR)
      self._local_img = (
        Qegd.IMGS_DIR + urlparse(self._img).path.rsplit("/", 1)[-1]
      )
      if not os.path.exists(self._local_img):
        helper.info("online qemu image starting download")
        urlretrieve(self._img, self._local_img)
        helper.info(f"saved image to {self._local_img}")
    copyfile(self._local_img, Qegd.CURRENT_IMG)

  METADATA_FILE = QEMU_DIR + "metadata.yaml"
  _METADATA = """instance-id: iid-local01
local-hostname: cloudimg
"""
  USER_DATA_FILE = QEMU_DIR + "user-data.yaml"
  _USER_DATA = """#cloud-config
users:
  - default
  - name: {user}
    groups: sudo
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - {pubkey}
"""

  SEED_FILE = QEMU_DIR + "seed.img"

  _GENERATE_SEED_IMG = (
    f"cloud-localds {SEED_FILE} {USER_DATA_FILE} {METADATA_FILE}"
  )

  def _setup_seed(self):
    """
    create seed.img with config data like ssh keypair in .qemu
    """
    if not which("cloud-localds"):
      helper.error("cloud-image-utils is not installed")

    if os.path.exists(Qegd.SEED_FILE):
      os.remove(Qegd.SEED_FILE)
    with open(Qegd.METADATA_FILE, "w") as metadata_file:
      metadata_file.write(Qegd._METADATA)
    helper.generate_keypair()
    with open(Qegd.USER_DATA_FILE, "w") as user_data_file:
      with open(Pwngd.PUBKEYFILE, "r") as pubkey_file:
        pubkey = pubkey_file.readline()
      user_data_file.write(
        Qegd._USER_DATA.format(pubkey=pubkey, user=self._user)
      )
    os.system(Qegd._GENERATE_SEED_IMG)

  _QEMU_PORT_FORWARDING = ",hostfwd={type}::{guest}-:{host}"
  _QEMU_START = (
    "{qemu} "
    + "{machine} "
    + "{cores} "
    + "{cpu} "
    + "{memory} "
    + "-nographic "
    + "{bios} "
    + "-device virtio-net-pci,netdev=net0 "
    + "-netdev user,id=net0,hostfwd=tcp::{port}-:22"
    + "{ports} "
    + "-drive if=virtio,format=qcow2,file={img} "
    + "-drive if=virtio,format=raw,file={seed} "
    + "{custom} "
  )

  _QEMU_PIPE = "&> /dev/null; "

  _QEMU_SUFFIX = "rm {lock} {current}"

  _QEMU_ARM_START = ""
  LOCKFILE = QEMU_DIR + "qemu.lock"

  def _qemu_start(self):
    """
    start qemu machine
    """
    self._lock(Qegd.TYPE)
    helper.info(f"starting qemu machine, ssh port {self._port}")
    with open(Qegd.LOCKFILE, "w") as lockfile:
      lockfile.write(str(self._port))
    port_forwarding = "".join(
      Qegd._QEMU_PORT_FORWARDING.format(
        type=host.split("/")[1], host=host.split("/")[0], guest=guest
      )
      for host, guest in self._forward.items()
    )
    qemu_cmd = Qegd._QEMU_START.format(
      qemu=self._qemu,
      machine=f"{Qegd.DEFAULT_QEMU_MACHINE_PREFIX} {self._machine}"
      if self._machine
      else "",
      cores=f"{Qegd.DEFAULT_QEMU_CORES_PREFIX} {self._cores}"
      if self._cores
      else "",
      cpu=f"{Qegd.DEFAULT_QEMU_CPU_PREFIX} {self._cpu}" if self._cpu else "",
      memory=f"{Qegd.DEFAULT_QEMU_MEMORY_PREFIX} {self._memory}"
      if self._memory
      else "",
      bios=f"{Qegd.DEFAULT_QEMU_BIOS_PREFIX} {self._bios}"
      if self._bios
      else "",
      port=self._port,
      ports=port_forwarding,
      img=Qegd.CURRENT_IMG,
      custom=self._custom if self._custom else "",
      seed=Qegd.SEED_FILE,
    )
    qemu_suffix = Qegd._QEMU_SUFFIX.format(
      lock=f"{Qegd.LOCKFILE} {Pwngd.LOCKFILE}", current=Qegd.CURRENT_IMG
    )

    helper.info(qemu_cmd)
    if self._detach:
      pwnlib.util.misc.run_in_new_terminal(qemu_cmd, kill_at_exit=False)
    else:
      pid = os.fork()
      if pid == 0:
        if self._detach:
          pass
        else:
          qemu_cmd += Qegd._QEMU_PIPE + qemu_suffix
          os.system(qemu_cmd)
        exit(0)

  def _new_vm(self) -> None:
    """
    create new vm
    """
    self.is_new = True

    helper.info(f"no Lockfile in {Qegd.LOCKFILE}")
    self._set_local_img()
    self._setup_seed()
    self._port = helper.first_free_port(Qegd.DEFAULT_PORT)
    # start qemu in independent process
    self._qemu_start()
    time.sleep(15)

  def _vm_setup(self) -> None:
    """
    setup qemu machine
    """
    self._host = Qegd.DEFAULT_HOST
    if not os.path.exists(Qegd.LOCKFILE):
      self._new_vm()
    else:
      with open(Qegd.LOCKFILE, "r") as lockfile:
        self._port = int(lockfile.readline())
      if not helper.is_port_in_use(self._port):
        helper.info(
          f"Lockfile in {Qegd.LOCKFILE}, but no running machine detected. Creating new one"
        )
        os.remove(Qegd.LOCKFILE)
        self._new_vm()
      helper.info(
        f"Lockfile in {Qegd.LOCKFILE}. Using running qemu instance at port {self._port}"
      )
