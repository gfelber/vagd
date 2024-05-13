import os
import pwn
import stat
import typer
import importlib.metadata
from typing import Optional

DOGD = "vm = Dogd(exe.path, image=Box.DOCKER_JAMMY, ex=True, fast=True)  # Docker"
VAGD = "vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, ex=True, fast=True)  # Vagrant"
QEGD = "vm = Qegd(exe.path, img=Box.QEMU_JAMMY, user='ubuntu', ex=True, fast=True)  # Qemu"
SHGD = "vm = Shgd(exe.path, user='user', port=22, ex=True, fast=True)  # SSH"

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]})

def _version(value: bool) -> None:
    if value:
        version = importlib.metadata.version('vagd')
        typer.echo(f"VAGD v{version}")
        raise typer.Exit()
@app.callback()
def main(
        version: Optional[bool] = typer.Option(
            None,
            "--version",
            "-v",
            help="Show current vagd version and exit.",
            callback=_version,
            is_eager=True,
        ),
    ) -> None:
        pass

@app.command()
def template(
        binary: Optional[str] = typer.Argument('', help='Binary to Exploit'),
        ip: Optional[str] = typer.Argument('', help='Ip or Domain of the remote target'),
        port: Optional[int] = typer.Argument(0, help='port of the remote target'),
        output: Optional[str] = typer.Option('', '-o', help='output file of the template (also add +x), default stdout'),
        libc: Optional[str] = typer.Option('', '--libc', '-l', help='add libc to template'),
        aslr: Optional[bool] = typer.Option(False, '--aslr', '-a', help='enable gdb ASLR (default: disabled for gdb)'),
        dogd: Optional[bool] = typer.Option(False, '--dogd', '--docker', '-d', help='create docker template'),
        qegd: Optional[bool] = typer.Option(False, '--qegd', '--qemu', '-q', help='create qemu template'),
        vagd: Optional[bool] = typer.Option(False, '--vagd', '--vagrant', '-v', help='create vagrant template'),
        shgd: Optional[bool] = typer.Option(False, '--shgd', '--ssh', '-s', help='create ssh template'),
        local: Optional[bool] = typer.Option(False, '--local', help='create local template'),
):
    """
    creates a template
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
                                                  vms=('\n' + ' ' * 8).join(vms))

        if output:
            with open(output, 'w') as exploitFile:
                exploitFile.write(template)
            current_permissions = os.stat(output).st_mode
            new_permissions = current_permissions | (stat.S_IXUSR)
            os.chmod(output, new_permissions)
        else:
            typer.echo(template)
@app.command()
def info(
        binary: str = typer.Argument(..., help='Binary to analyse'),
    ):
    """
    analyses the binary, prints checksec and .comment (often includes Distro and Compiler info)
    """
    elf = pwn.ELF(binary)
    pwn.log.info(elf.section('.comment').decode().replace('\0', '\n'))


def start():
    app()
