import fileinput
import os
import re
from shutil import which
from typing import List

from vagd import helper, templates
from vagd.box import Box
from vagd.virts.pwngd import Pwngd
from vagd.virts.shgd import Shgd


class Vagd(Shgd):
  """
  | Vagrant Virtualization for pwntools

  :param binary: binary for VM debugging
  :param vbox: vagrant box to use
  :param vagrantfile: location of Vagrantfile
  :param packages: packages to install on vm
  :param kwargs: arguments to pass through to super

  | SSH from cmd:

  .. code-block::  bash

    vagd ssh
    # or
    VAGRANT_CWD=.vagd vagrant ssh

  | halt from cmd

  .. code-block:: bash

    VAGRANT_CWD=.vagd vagrant halt

  | destroy from cmd

  .. code-block:: bash

    vagd clean
    # or
    VAGRANT_CWD=.vagd vagrant destroy
  """

  VAGRANTFILE_PATH = Pwngd.LOCAL_DIR + "Vagrantfile"
  VAGRANTFILE_BOX = "config.vm.box"
  VAGRANT_BOX = Box.VAGRANT_JAMMY64
  KEYFILE = (
    Pwngd.LOCAL_DIR + ".vagd/.vagrant/machines/default/virtualbox/private_key"
  )
  TYPE = "vagd"

  _box: str
  _vagrantfile: str
  _v: object

  def _get_box(self) -> str:
    """
    returns box of current vagrantfile
    @:rtype box name of Vagrantfile
    """
    with open(self._vagrantfile, "r") as vagrantfile:
      for line in vagrantfile.readlines():
        if Vagd.VAGRANTFILE_BOX in line:
          pattern = rf'{Vagd.VAGRANTFILE_BOX} = "(.*?)"'
          match = re.search(pattern, line, re.DOTALL)
          if match:
            return match.group(1)
    return ""

  def _vm_setup(self) -> None:
    """
    setup vagrant machine creates new one if no Vagrantfile is specified or box does not match
    """

    if self._get_box() != self._box:
      helper.info("new box detected destroying old machine")
      self._v.destroy()
      for line in fileinput.input(self._vagrantfile, inplace=True):
        if Vagd.VAGRANTFILE_BOX in line:
          line = f'{Vagd.VAGRANTFILE_BOX} = "{self._box}"\n'
        print(line, end="")

    if self._v.status()[0].state == "not_created":
      self.is_new = True
      helper.info("initialing new vagrant vm might take a while")
      self._v.up()

    if self._v.status()[0].state != "running":
      helper.info("starting existing vagrant machine")
      self._v.up()

  def __init__(
    self,
    binary: str,
    vagrantfile: str = VAGRANTFILE_PATH,
    vbox: str = None,
    packages: List[str] = None,
    **kwargs,
  ):
    """

    :param binary: binary for VM debugging
    :param vbox: vagrant box to use
    :param vagrantfile: location of Vagrantfile
    :param packages: packages to install on vm
    :param kwargs: arguments to pass through to super
    """
    import vagrant

    helper.warn("The 'Vagd' object is deprecated, use 'Qegd' instead")

    if packages is None:
      packages = list()

    if not which("vagrant"):
      helper.error("vagrant isn't installed")

    if not os.path.exists(Pwngd.LOCAL_DIR):
      os.makedirs(Pwngd.LOCAL_DIR)

    self._vagrantfile = vagrantfile

    if vbox is None:
      if os.path.exists(vagrantfile):
        vbox = self._get_box()
      else:
        vbox = Vagd.VAGRANT_BOX

    self._box = vbox

    self._lock(Vagd.TYPE)
    if not os.path.isfile(self._vagrantfile):
      helper.info("creating new Vagrantfile")
      vagrant_config = templates.VAGRANT_TEMPLATE.format(box=self._box)
      with open(self._vagrantfile, "w") as file:
        file.write(vagrant_config)

    self._v = vagrant.Vagrant(os.path.dirname(self._vagrantfile))

    self._vm_setup()

    packages += Pwngd.DEFAULT_PACKAGES

    super().__init__(
      binary=binary,
      user=self._v.user(),
      host=self._v.hostname(),
      port=int(self._v.port()),
      packages=packages,
      keyfile=self._v.keyfile(),
      **kwargs,
    )
