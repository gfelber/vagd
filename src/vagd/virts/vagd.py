import os
import re
import pwn
import vagrant
import fileinput
from shutil import which

from vagd import templates
from vagd.box import Box
from vagd.virts.pwngd import Pwngd
from vagd.virts.shgd import Shgd


class Vagd(Shgd):
    """
    | Vagrant Virtualization for pwntools
    |
    | SSH from cmd:
    .. code-block::  bash

        VAGRANT_CWD=.vagd vagrant ssh

    | halt from cmd
    .. code-block:: bash

        VAGRANT_CWD=.vagd vagrant halt

    | destroy from cmd
    .. code-block:: bash

        VAGRANT_CWD=.vagd vagrant destroy
    """

    VAGRANTFILE_PATH = Pwngd.LOCAL_DIR + 'Vagrantfile'
    VAGRANTFILE_BOX = 'config.vm.box'
    VAGRANT_BOX = Box.UBUNTU_FOCAL64

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
            vagrant_config = templates.VAGRANT_TEMPLATE.format(box=self._box, packages=' '.join(Pwngd.DEFAULT_PACKAGES))
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

        if not os.path.exists(Pwngd.LOCAL_DIR):
            os.makedirs(Pwngd.LOCAL_DIR)

        self._vagrantfile = vagrantfile

        if vbox is None:
            if os.path.exists(vagrantfile):
                vbox = self._get_box()
            else:
                vbox = Vagd.VAGRANT_BOX

        self._box = vbox
        self._v = vagrant.Vagrant(os.path.dirname(vagrantfile))

        self._vm_setup()

        super().__init__(binary=binary,
                         user=self._v.user(),
                         host=self._v.hostname(),
                         port=int(self._v.port()),
                         keyfile=self._v.keyfile(), **kwargs)
