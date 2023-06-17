import os
import sys

import pwn
import time
import requests

from typing import Dict
from urllib.parse import urlparse
from shutil import which, copyfile

from vagd import helper
from vagd.box import Box
from vagd.virts.pwngd import Pwngd


class Qegd(Pwngd):
    """
    | QEMU Virtualization for pwntools
    | SSH from cmd

    .. code-block:: bash

        ssh -o "StrictHostKeyChecking=no" -i ~/.vagd/keyfile -p $(cat .vagd/qemu.lock) ubuntu@0.0.0.0

    | Kill from cmd:

    .. code-block:: bash

        kill $(pgrep qemu)

    | Qemu images are cached in the home directory: :code:`~/.vagd/qemu-imgs/`
    |
    | current used images are stored in the local directory: :code:`./.vagd/current.img`
    | These should be deleted automatically, but if a machine gets improperly stopped
    | (shutdown host while vm is running) it might remain and use up space. You can find remaining images with:

    .. code-block:: bash
        
        find ~/ -name current.img
        rm <path/current.img>

    """

    DEFAULT_IMG = Box.CLOUDIMAGE_FOCAL
    QEMU_DIR = Pwngd.LOCAL_DIR
    IMGS_DIR = Pwngd.HOME_DIR + 'qemu-imgs/'
    DEFAULT_USER = 'ubuntu'
    DEFAULT_HOST = '0.0.0.0'
    DEFAULT_PORT = 2222
    ARM_FLASH = "/usr/share/AAVMF/AAVMF_CODE.fd"
    DEFAULT_QEMU_ARM_PFLASH_OPTIONS = ""
    DEFAULT_QEMU_ARM_PFLASH = QEMU_DIR + "flash.img"
    DEFAULT_QEMU_CMD = "qemu-system-x86_64"
    DEFAULT_QEMU_ARM_CMD = "qemu-system-aarch64"
    DEFAULT_QEMU_MACHINE_PREFIX = "-machine"
    DEFAULT_QEMU_MACHINE = "accel=kvm,type=q35"
    DEFAULT_QEMU_ARM_MACHINE = "virt"
    DEFAULT_QEMU_CPU_PREFIX = "-cpu"
    DEFAULT_QEMU_CPU = "host"
    DEFAULT_QEMU_ARM_CPU = "cortex-a57"
    DEFAULT_QEMU_PFLASH_PREFIX = "-pflash"

    _img: str
    _new: bool = False
    _local_img: str
    _user: str
    _host: str
    _port: int
    _ports: Dict[int, int]
    _qemu: str
    _cpu: str
    _machine: str
    _keyfile: str

    @staticmethod
    def _is_local(url) -> bool:
        """
        check if provided url is local or remote
        :param url: url to check
        :return: if the url is local or remote
        """
        url_parsed = urlparse(url)
        if url_parsed.scheme in ('file', ''):  # Possibly a local file
            return os.path.exists(url_parsed.path)
        return False

    CURRENT_IMG = QEMU_DIR + "current.img"

    def _set_local_img(self):
        """
        get local image for qemu machine
        """
        if Qegd._is_local(self._img):
            pwn.log.info("Using local image")
            self._local_img = self._img
        else:
            if not os.path.exists(Qegd.IMGS_DIR):
                os.makedirs(Qegd.IMGS_DIR)
            self._local_img = Qegd.IMGS_DIR + urlparse(self._img).path.rsplit('/', 1)[-1]
            if not os.path.exists(self._local_img):
                pwn.log.info("online qemu image starting download")
                img = requests.get(self._img)
                with open(self._local_img, 'wb') as imgfile:
                    pwn.log.info(f"saving image to {self._local_img}")
                    imgfile.write(img.content)
        copyfile(self._local_img, Qegd.CURRENT_IMG)

    METADATA_FILE = QEMU_DIR + 'metadata.yaml'
    _METADATA = """instance-id: iid-local01
local-hostname: cloudimg
"""
    USER_DATA_FILE = QEMU_DIR + 'user-data.yaml'
    _USER_DATA = """#cloud-config
ssh_authorized_keys:
  - {pubkey}
"""

    SEED_FILE = QEMU_DIR + "seed.img"

    _GENERATE_SEED_IMG = f'cloud-localds {SEED_FILE} {USER_DATA_FILE} {METADATA_FILE}'

    def _setup_seed(self):
        """
        create seed.img with config data like ssh keypair in .qemu
        """
        if not which('cloud-localds'):
            pwn.log.error("cloud-image-utils is not installed")
        if not os.path.exists(Qegd.SEED_FILE):
            pwn.log.info(f"{Qegd.SEED_FILE} not found generating new one")
            if not os.path.exists(Qegd.METADATA_FILE):
                pwn.log.info(f"{Qegd.METADATA_FILE} not found generating new one")
                with open(Qegd.METADATA_FILE, 'w') as metadata_file:
                    metadata_file.write(Qegd._METADATA)
            if not os.path.exists(Qegd.USER_DATA_FILE):
                pwn.log.info(f"{Qegd.USER_DATA_FILE} not found generating new one")
                helper.generate_keypair()
                with open(Qegd.USER_DATA_FILE, 'w') as user_data_file:
                    with open(Pwngd.PUBKEYFILE, 'r') as pubkey_file:
                        pubkey = pubkey_file.readline()
                    user_data_file.write(Qegd._USER_DATA.format(pubkey=pubkey))
            os.system(Qegd._GENERATE_SEED_IMG)

    _QEMU_PORT_FORWARDING = ',hostfwd=tcp::{host}-:{guest}'
    _QEMU_START = "{qemu} " \
                  + "{machine} " \
                  + "{cpu} " \
                  + "-m 2G " \
                  + "-nographic " \
                  + "{pflash} " \
                  + "-device virtio-net-pci,netdev=net0 " \
                  + "-netdev user,id=net0,hostfwd=tcp::{port}-:22" \
                  + "{ports} " \
                  + "-drive if=virtio,format=qcow2,file={img} " \
                  + "-drive if=virtio,format=raw,file={seed} " \
                  + "{custom} " \
                  + "> /dev/null; " \
                  + "rm {lock} {current}"

    _QEMU_ARM_START = ""
    LOCKFILE = QEMU_DIR + "qemu.lock"

    def _qemu_start(self):
        """
        start qemu machine
        """
        pwn.log.info(f"starting qemu machine, ssh port {self._port}")
        with open(Qegd.LOCKFILE, 'w') as lockfile:
            lockfile.write(str(self._port))
        pid = os.fork()
        if pid == 0:
            copyfile(Qegd.ARM_FLASH, Qegd.DEFAULT_QEMU_ARM_PFLASH)
            qemu_cmd = Qegd._QEMU_START.format(qemu=self._qemu,
                                               machine=" ".join((Qegd.DEFAULT_QEMU_MACHINE_PREFIX,
                                                                 self._machine)) if self._machine else '',
                                               cpu=" ".join(
                                                   (Qegd.DEFAULT_QEMU_CPU_PREFIX, self._cpu)) if self._cpu else '',
                                               pflash=" ".join((Qegd.DEFAULT_QEMU_PFLASH_PREFIX,
                                                                self._pflash)) if self._pflash else '',
                                               port=self._port,
                                               ports="".join(
                                                   [Qegd._QEMU_PORT_FORWARDING.format(host=host, guest=guest) for
                                                    host, guest in self._ports.items()]),
                                               img=Qegd.CURRENT_IMG,
                                               custom='',
                                               seed=Qegd.SEED_FILE,
                                               lock=Qegd.LOCKFILE,
                                               current=Qegd.CURRENT_IMG)
            pwn.log.info(qemu_cmd)
            os.system(qemu_cmd)
            sys.exit(0)

    def _new_vm(self) -> None:
        """
        create new vm
        """
        self._new = True

        pwn.log.info(f"no Lockfile in {Qegd.LOCKFILE}")
        self._set_local_img()
        self._setup_seed()
        # start qemu in independent process
        self._port = helper.first_free_port(Qegd.DEFAULT_PORT)
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
            with open(Qegd.LOCKFILE, 'r') as lockfile:
                self._port = int(lockfile.readline())
            if not helper.is_port_in_use(self._port):
                pwn.log.info(f'Lockfile in {Qegd.LOCKFILE}, but no running machine detected. Creating new one')
                os.remove(Qegd.LOCKFILE)
                self._new_vm()
            pwn.log.info(f'Lockfile in {Qegd.LOCKFILE}. Using running qemu instance at port {self._port}')

    _TRIES = 3  # three times the charm

    def _ssh_setup(self) -> None:
        """
        setup ssh connection to QEMU
        """
        for _ in range(Qegd._TRIES):
            try:
                self._ssh = pwn.ssh(
                    user=self._user,
                    host=self._host,
                    port=self._port,
                    keyfile=Pwngd.KEYFILE,
                    ignore_config=True
                )
                break
            except:
                if _ + 1 == Qegd._TRIES:
                    pwn.log.error('SSH failed, pls try again')
                else:
                    pwn.log.info('Trying again')
                time.sleep(15)

    def __init__(self,
                 binary: str,
                 img: str = DEFAULT_IMG,
                 user: str = DEFAULT_USER,
                 ports: Dict[int, int] = None,
                 arm: bool = False,
                 qemu: str = DEFAULT_QEMU_CMD,
                 machine: str = DEFAULT_QEMU_MACHINE,
                 cpu: str = DEFAULT_QEMU_CPU,
                 pflash: str = None,
                 **kwargs):
        """

        :param binary: binary for VM debugging
        :param img: qemu image to use (requires ssh)
        :param user: user inside qemu image
        :param ports: forwarded ports
        :param arm: if qemu is arm
        :param qemu: qemu cmd
        :param cpu: value for :code -cpu
        :param machine: value for :code -machine
        :param pflash: value for :code -pflash
        :param kwargs: parameters to pass through to super
        """

        if not which('qemu-system-x86_64'):
            pwn.log.error('qemu-system-x86_64 isn\'t installed')

        if not os.path.exists(Qegd.QEMU_DIR):
            pwn.log.info(f"Generating {Qegd.QEMU_DIR} dir")
            os.makedirs(Qegd.QEMU_DIR)

        if arm:
            qemu = Qegd.DEFAULT_QEMU_ARM_CMD if qemu == Qegd.DEFAULT_QEMU_CMD else qemu
            cpu = Qegd.DEFAULT_QEMU_ARM_CPU if cpu == Qegd.DEFAULT_QEMU_CPU else cpu
            machine = Qegd.DEFAULT_QEMU_ARM_MACHINE if machine == Qegd.DEFAULT_QEMU_MACHINE else machine
            pflash = Qegd.DEFAULT_QEMU_ARM_PFLASH_OPTIONS + Qegd.DEFAULT_QEMU_ARM_PFLASH if pflash is None else pflash

        self._img = img
        self._user = user
        self._ports = ports if ports else dict()
        self._arm = arm
        self._qemu = qemu
        self._cpu = cpu
        self._machine = machine
        self._pflash = pflash

        self._vm_setup()
        self._ssh_setup()
        if self._new:
            self._install_packages(Pwngd.DEFAULT_PACKAGES)

        super().__init__(binary=binary, **kwargs)
