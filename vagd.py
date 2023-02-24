import vagrant
import os
from typing import Collection, Union
import re
import pwn
from vtemplate import VAGRANT_TEMPLATE


class Vagd:
    VAGRANTFILE_PATH = './Vagrantfile'
    VAGRANT_BOX = 'ubuntu/focal64'

    _box: str
    _vagrantfile: str
    _v: vagrant
    _ssh: pwn.ssh
    _gdb: pwn.gdb
    _binary: pwn.gdb

    def _get_box(self) -> str:
        if os.path.isfile(self._vagrantfile):
            with open(self._vagrantfile, 'r') as vagrantfile:
                for line in vagrantfile.readlines():
                    if 'config.vm.box' in line:
                        pattern = r'config.vm.box = "(.*?)"'
                        match = re.search(pattern, line, re.DOTALL)
                        if match:
                            return match.group(1)
        return ''

    def _vagrant_setup(self):
        if self._get_box() != self._box:
            self._v.destroy()
            vagrant_config = VAGRANT_TEMPLATE.format(self._box)
            with open(self._vagrantfile, 'w') as file:
                file.write(vagrant_config)

        self._v.up()

    def __init__(self,
                 binary: str,
                 box: str = VAGRANT_BOX,
                 vagrantfile: str = VAGRANTFILE_PATH,
                 files: Union[str, tuple[str]] = []):
        self._binary = './' + os.path.basename(binary)
        self._box = box
        self._vagrantfile = vagrantfile
        self._v = vagrant.Vagrant(self._vagrantfile.replace('Vagrantfile', ''))

        self._vagrant_setup()

        # setup ssh and upload files
        self._ssh = pwn.ssh(
            user=self._v.user(),
            host=self._v.hostname(),
            port=int(self._v.port()),
            keyfile=self._v.keyfile()
        )
        self._ssh.set_working_directory()

        self._ssh.put(binary)
        self._ssh.run('chmod +x ' + self._binary)

        if isinstance(files, str):
            self._ssh.put(files)
            self._ssh
        elif isinstance(files, tuple):
            for file in files:
                self._ssh.put(file)

    def start(self, argv: Collection = ('',), gdbscript: str = '', *a, **kw) -> pwn.process:
        if pwn.args.GDB:
            return pwn.gdb.debug((self._binary,) + argv, ssh=self._ssh, gdbscript=gdbscript, *a, **kw)
        else:
            return self._ssh.process((self._binary,) + argv, *a, **kw)


def main():
    vagd = Vagd('./test/sysinfo')
    t = vagd.start()
    print(pwn.args.values())
    t.interactive()


if __name__ == '__main__':
    main()
