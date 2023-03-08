import os
import re
import time
import pwn
import vagrant
import requests
import fileinput
from typing import Iterable
from shutil import which, copyfile
from urllib.parse import urlparse
from multiprocessing import Process
from vagd import vtemplate, box, wrapper, gdb, pwngd


class Vagd(pwngd.Pwngd):
    VAGRANTFILE_PATH = './Vagrantfile'
    VAGRANTFILE_BOX = 'config.vm.box'
    VAGRANT_BOX = box.UBUNTU_FOCAL64

    _box: str
    _vagrantfile: str
    _v: vagrant

    def _get_box(self) -> str:
        """
        returns box of current vagrantfile
        @:rtype box name of Vagrantfile
        """
        with open(self._vagrantfile, 'r') as vagrantfile:
            for line in vagrantfile.readlines():
                if Vagd.VAGRANTFILE_BOX in line:
                    pattern = fr'{Vagd.VAGRANTFILE_BOX} = "(.*?)"'
                    match = re.search(pattern, line, re.DOTALL)
                    if match:
                        return match.group(1)
        return ''

    def _vm_setup(self) -> None:
        """
        setup vagrant machine creates new one if no Vagrantfile is specified or box does not match
        """

        if not os.path.isfile(self._vagrantfile):
            pwn.log.info('creating new Vagrantfile')
            vagrant_config = vtemplate.VAGRANT_TEMPLATE.format(self._box)
            with open(self._vagrantfile, 'w') as file:
                file.write(vagrant_config)
            pwn.log.info('initialing new vagrant vm might take a while')
            self._v.up()

        elif self._get_box() != self._box:
            pwn.log.info('new box detected destroying old machine')
            self._v.destroy()
            for line in fileinput.input(self._vagrantfile, inplace=True):
                if Vagd.VAGRANTFILE_BOX in line:
                    line = f'{Vagd.VAGRANTFILE_BOX} = "{self._box}"\n'
                print(line, end='')
            pwn.log.info('initialing new vagrant vm might take a while')
            self._v.up()

        if self._v.status()[0].state != 'running':
            pwn.log.info('starting existing vagrant machine')
            self._v.up()

    def _ssh_setup(self) -> None:
        """
        setup ssh connection to vagrant
        """
        self._ssh = pwn.ssh(
            user=self._v.user(),
            host=self._v.hostname(),
            port=int(self._v.port()),
            keyfile=self._v.keyfile(),
            ignore_config=True
        )

    def __init__(self,
                 binary: str,
                 vagrantfile: str = VAGRANTFILE_PATH,
                 vbox: str = None,
                 **kwargs):
        """

        :param binary: binary for VM debugging
        :param vbox: vagrant box to use
        :param vagrantfile: location of Vagrantfile
        :param kwargs: arguments to pass through to super
        """

        if not which('vagrant'):
            pwn.log.error('vagrant isn\'t installed')

        self._vagrantfile = vagrantfile

        if vbox is None:
            if os.path.exists(vagrantfile):
                vbox = self._get_box()
            else:
                vbox = Vagd.VAGRANT_BOX

        self._box = vbox
        self._v = vagrant.Vagrant(os.path.dirname(vagrantfile))

        self._vm_setup()
        self._ssh_setup()

        super().__init__(binary=binary, **kwargs)


class Qegd(pwngd.Pwngd):
    DEFAULT_IMG = 'https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img'
    QEMU_DIR = './.qemu/'
    IMG_DIR = QEMU_DIR + 'qemu-img/'
    DEFAULT_USER = 'ubuntu'
    DEFAULT_HOST = '0.0.0.0'
    DEFAULT_PORT = 2222
    KEYFILE = QEMU_DIR + 'keyfile'

    _img: str
    _new: bool = False
    _local_img: str
    _user: str
    _host: str
    _port: int
    _keyfile: str

    @staticmethod
    def _is_local(url):
        url_parsed = urlparse(url)
        if url_parsed.scheme in ('file', ''):  # Possibly a local file
            return os.path.exists(url_parsed.path)
        return False

    @staticmethod
    def _is_port_in_use(port: int) -> bool:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    CURRENT_IMG = QEMU_DIR + "current.img"

    def _set_local_img(self):
        if Qegd._is_local(self._img):
            pwn.log.info("Using local image")
            self._local_img = self._img
        else:
            if not os.path.exists(Qegd.IMG_DIR):
                os.makedirs(Qegd.IMG_DIR)
            self._local_img = Qegd.IMG_DIR + urlparse(self._img).path.rsplit('/', 1)[-1]
            if not os.path.exists(self._local_img):
                pwn.log.info("online qemu image starting download")
                img = requests.get(self._img)
                with open(self._local_img, 'wb') as imgfile:
                    imgfile.write(img.content)
        copyfile(self._local_img, Qegd.CURRENT_IMG)

    GENERATE_KEYPAIR = 'ssh-keygen -q -t ed25519 -f {keyfile} -N ""'

    def _generate_keypair(self):
        if not (os.path.exists(Qegd.KEYFILE) and os.path.exists(Qegd.KEYFILE + '.pub')):
            pwn.log.info("No Keypair was found. Generating new keypair")
            os.system(Qegd.GENERATE_KEYPAIR.format(keyfile=Qegd.KEYFILE))

    METADATA_FILE = QEMU_DIR + 'metadata.yaml'
    METADATA = """instance-id: iid-local01
local-hostname: cloudimg
"""
    USER_DATA_FILE = QEMU_DIR + 'user-data.yaml'
    USER_DATA = """#cloud-config
ssh_authorized_keys:
  - {pubkey}
"""

    SEED_FILE = QEMU_DIR + "seed.img"

    GENERATE_SEED_IMG = f'cloud-localds {SEED_FILE} {USER_DATA_FILE} {METADATA_FILE}'

    def _setup_seed(self):
        if not which('cloud-localds'):
            pwn.log.error("cloud-image-utils is not installed")
        if not os.path.exists(Qegd.SEED_FILE):
            pwn.log.info(f"{Qegd.SEED_FILE} not found generating new one")
            if not os.path.exists(Qegd.METADATA_FILE):
                pwn.log.info(f"{Qegd.METADATA_FILE} not found generating new one")
                with open(Qegd.METADATA_FILE, 'w') as metadata_file:
                    metadata_file.write(Qegd.METADATA)
            if not os.path.exists(Qegd.USER_DATA_FILE):
                pwn.log.info(f"{Qegd.USER_DATA_FILE} not found generating new one")
                self._generate_keypair()
                with open(Qegd.USER_DATA_FILE, 'w') as user_data_file:
                    with open(Qegd.KEYFILE + '.pub', 'r') as pubkey_file:
                        pubkey = pubkey_file.readline()
                    user_data_file.write(Qegd.USER_DATA.format(pubkey=pubkey))
            os.system(Qegd.GENERATE_SEED_IMG)

    QEMU_START = "qemu-system-x86_64 " \
                 + "-machine accel=kvm,type=q35 " \
                 + "-cpu host " \
                 + "-m 2G " \
                 + "-nographic " \
                 + "-device virtio-net-pci,netdev=net0 " \
                 + "-netdev user,id=net0,hostfwd=tcp::{port}-:22 " \
                 + "-drive if=virtio,format=qcow2,file={img} " \
                 + "-drive if=virtio,format=raw,file={seed} " \
                 + "> /dev/null; " \
                 + "rm {lock}"

    LOCKFILE = QEMU_DIR + "qemu.lock"

    def _qemu_start(self):
        pwn.log.info("starting qemu machine")
        with open(Qegd.LOCKFILE, 'w') as lockfile:
            lockfile.write(str(self._port))
        pid = os.fork()
        if pid == 0:
            os.system(Qegd.QEMU_START.format(port=self._port,
                                             img=Qegd.CURRENT_IMG,
                                             seed=Qegd.SEED_FILE,
                                             lock=Qegd.LOCKFILE)
                      )

    def _new_vm(self) -> None:
        self._new = True
        for i in range(101):
            if not self._is_port_in_use(Qegd.DEFAULT_PORT + i):
                self._port = Qegd.DEFAULT_PORT + i
                break

        pwn.log.info(f"no Lockfile in {Qegd.LOCKFILE}, new qemu instance is started at port {self._port}")
        self._set_local_img()
        self._setup_seed()
        # start qemu in independent process
        self._qemu_start()
        time.sleep(20)

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
            if not Qegd._is_port_in_use(self._port):
                pwn.log.info(f'Lockfile in {Qegd.LOCKFILE}, but no running machine detected. Creating new one')
                os.remove(Qegd.LOCKFILE)
                self._new_vm()
            pwn.log.info(f'Lockfile in {Qegd.LOCKFILE}. Using running qemu instance at port {self._port}')

    def _ssh_setup(self) -> None:
        """
        setup ssh connection to vagrant
        """
        self._ssh = pwn.ssh(
            user=self._user,
            host=self._host,
            port=self._port,
            keyfile=Qegd.KEYFILE,
            ignore_config=True
        )

    def _install_packages(self, packages: Iterable):
        self.system("sudo apt update").recvall()
        packages_str = " ".join(packages)
        self.system(f"sudo apt install -y {packages_str}").recvall()

    DEFAULT_PACKAGES = ['gdbserver', 'libc6-dbg']

    def __init__(self,
                 binary: str,
                 img: str = DEFAULT_IMG,
                 user: str = DEFAULT_USER,
                 packages: Iterable = None,
                 **kwargs):
        """

        :param binary: binary for VM debugging
        :param img: qemu image to use (requires ssh)
        :param user: user inside qemu image
        :param packages: packages to install
        :param kwargs: parameters to pass through to super
        """

        if not which('qemu-system-x86_64'):
            pwn.log.error('qemu-system-x86_64 isn\'t installed')

        if not os.path.exists(Qegd.QEMU_DIR):
            pwn.log.info("Generating .qemu dir")
            os.makedirs(Qegd.QEMU_DIR)

        self._img = img
        self._user = user

        self._vm_setup()
        self._ssh_setup()
        if self._new:
            self._install_packages(Qegd.DEFAULT_PACKAGES)
        if packages:
            self._install_packages(packages)

        super().__init__(binary=binary, **kwargs)
