import os
import re
import pwn
import vagrant
import fileinput
from shutil import which
from typing import Union
from vagd import vtemplate, box, wrapper, gdb, pwngd


class Vagd(pwngd.Pwngd):
    VAGRANTFILE_PATH = './Vagrantfile'
    VAGRANTFILE_BOX = 'config.vm.box'

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
                 files: Union[str, list[str]] = None,
                 tmp: bool = False,
                 fast: bool = False,
                 ex: bool = False):
        """

        :param binary: binary for VM debugging
        :param vbox: vagrant box to use
        :param vagrantfile: location of Vagrantfile
        :param files: other files or directories that need to be uploaded to VM
        :param tmp: if a temporary directory should be created for files
        :param fast: mounts libs locally for faster symbol extraction (experimental)
        :param ex: if experimental features should be enabled
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

        super(Vagd, self).__init__(binary=binary, files=files, tmp=tmp, fast=fast, ex=ex)
