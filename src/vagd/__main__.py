import os
import stat
import typer

DOGD = "vm = Dogd(exe.path, image=Box.DOCKER_JAMMY, ex=True, fast=True)  # Docker"
VAGD = "vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, ex=True, fast=True)  # Vagrant"
QEGD = "vm = Qegd(exe.path, img=Box.QEMU_JAMMY, user='ubuntu', ex=True, fast=True)  # Qemu"
SHGD = "vm = Shgd(exe.path, user='user', port=22, ex=True, fast=True)  # SSH"


def main(
            binary: str = typer.Argument('', help='Binary to Exploit'),
            ip: str = typer.Argument('', help='Ip or Domain of the remote target'),
            port: int = typer.Argument(0, help='port of the remote target'),
            output: str = typer.Option('', '-o', help = 'output file of the template, default stdout'),
            libc: str = typer.Option('', '--libc', help='add libc to template'),
            aslr: bool = typer.Option(False, '--aslr', help='enable gdb ASLR (default: disabled for gdb)'),
            dogd: bool = typer.Option(False, '--dogd', help='create docker template'),
            qegd: bool = typer.Option(False, '--qegd', help='create qemu template'),
            vagd: bool = typer.Option(False, '--vagd', help='create vagrant template'),
            shgd: bool = typer.Option(False, '--shgd', help='create ssh template'),
            local: bool = typer.Option(False, '--local', help='create local template'),
    ):
    """
    creates a template
    :param binary: the binary to exploit
    :param ip: the ip/domain of the remote target
    :param port: the port of the remote target
    :param output: output file
    """
    templatePath = os.path.dirname(os.path.realpath(__file__))
    templateChunks = []
    templatePath += '/res/local_template.txt' if local else '/res/template.txt'
    multi = False
    if not any((dogd, qegd, vagd, shgd)):
        dogd = qegd = vagd = shgd = True
        multi = True

    dependencies = []
    vms = []
    if dogd:
        dependencies.append('Dogd')
        vms.append(DOGD)
    if qegd:
        dependencies.append('Qegd')
        vms.append(('# ' if multi else '') + QEGD)
    if vagd:
        dependencies.append('Vagd')
        vms.append(('# ' if multi else '') + VAGD)
    if shgd:
        dependencies.append('Shgd')
        vms.append(('# ' if multi else '') + SHGD)

    with open(templatePath, 'r') as templateFile:
        for line in templateFile.readlines():

            if not libc and line.startswith('libc'):
                continue
            templateChunks.append(line)

        template = ''.join(templateChunks).format('{}',
                                                  binary=binary,
                                                  ip=ip,
                                                  port=str(port),
                                                  libc=libc,
                                                  aslr=aslr,
                                                  dependencies=', '.join(dependencies),
                                                  vms=('\n'+ ' '*8).join(vms))

        if output:
            with open(output, 'w') as exploitFile:
                exploitFile.write(template)
            current_permissions = os.stat(output).st_mode
            new_permissions = current_permissions | (stat.S_IXUSR)
            os.chmod(output, new_permissions)
        else:
            print(template, end='')


if __name__ == '__main__':
    typer.run(main)
