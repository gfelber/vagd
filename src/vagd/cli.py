import importlib.metadata
import os
import stat
import sys
from typing import Optional, Dict

import pwn
import typer

import vagd
# prevents term.init
from vagd.virts.dogd import Dogd
from vagd.virts.qegd import Qegd
from vagd.virts.vagd import Vagd
from vagd.virts.pwngd import Pwngd

DOGD = "vm = Dogd(exe.path, image=Box.DOCKER_JAMMY, ex=True, fast=True)  # Docker"
VAGD = "vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, ex=True, fast=True)  # Vagrant"
QEGD = "vm = Qegd(exe.path, img=Box.QEMU_JAMMY, ex=True, fast=True)  # Qemu"
SHGD = "vm = Shgd(exe.path, user='user', host='localhost', port=22, ex=True, fast=True)  # SSH"

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
        output_exploit: Optional[bool] = typer.Option(False, '-e', help='output file of the template (also add +x) to exploit.py'),
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

        if output_exploit:
            output = 'exploit.py'
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


def _get_type() -> str:
    if os.path.exists(Pwngd.LOCKFILE):
        with open(Pwngd.LOCKFILE) as lfile:
            return lfile.read()
    sys.stderr.write("no vagd instance is running\n")
    exit(1)


def _exec(cmd: str, env: Dict = None):
    if env is None:
        env = os.environ
    else:
        env.update(os.environ)
    os.execvpe("sh", ('sh', '-c', cmd), env)


def _ssh(port, user):
    os.system(
        f'ssh -o "StrictHostKeyChecking=no" -i {Pwngd.KEYFILE} -p {port} {user}@0.0.0.0')

@app.command()
def ssh(
        user: Optional[str] = typer.Option(None, '--user', '-u', help='ssh user'),
):
    """
    ssh to current vagd instance (must be in exploit dir)
    """
    typ = _get_type()
    if typ == Dogd.TYPE:
        if user is None:
            user = Dogd.DEFAULT_USER
        with open(Dogd.LOCKFILE, 'r') as lfile:
            port = lfile.read().split(':')[1]
            _ssh(int(port), user)
    elif typ == Qegd.TYPE:
        if user is None:
            user = Qegd.DEFAULT_USER
        with open(Qegd.LOCKFILE, 'r') as lfile:
            _ssh(int(lfile.read()), user)
    elif typ == Vagd.TYPE:
        os.system(f'VAGRANT_CWD={Pwngd.LOCAL_DIR} vagrant ssh')
    else:
        sys.stderr.write(f"Unknown type in {Pwngd.LOCKFILE}: {typ}\n")
        exit(1)


def _scp(port: int, user: str, source: str, target: str, recursive: bool, keyfile: str = Pwngd.KEYFILE):
    options = '-R' if recursive else ''
    if ':' in source:
        file = source[source.find(':') + 1:]
        source = f'{user}@0.0.0.0:{file}'
    if ':' in target:
        file = target[target.find(':') + 1:]
        target = f'{user}@0.0.0.0:{file}'
    os.system(f'scp -P {port} -o StrictHostKeyChecking=no -i {keyfile} {options} {source} {target}')


@app.command()
def scp(
        source: str = typer.Argument(..., help='source file'),
        target: str = typer.Argument('vagd:./', help='target file'),
        recursive: bool = typer.Option(False, '-r', '--recursive', help='recursive copy'),
        user: Optional[str] = typer.Option(None, '--user', '-u', help='ssh user'),
):
    """
    scp to from current vagd instance (must be in exploit dir)
    """
    typ = _get_type()
    if typ == Dogd.TYPE:
        if user is None:
            user = Dogd.DEFAULT_USER
        with open(Dogd.LOCKFILE, 'r') as lfile:
            port = lfile.read().split(':')[1]
            _scp(int(port), user, source, target, recursive)
    elif typ == Qegd.TYPE:
        if user is None:
            user = Qegd.DEFAULT_USER
        with open(Qegd.LOCKFILE, 'r') as lfile:
            _scp(int(lfile.read()), user, source, target, recursive)
    elif typ == Vagd.TYPE:
        import vagrant
        v = vagrant.Vagrant(os.path.dirname(Vagd.VAGRANTFILE_PATH))
        _scp(2222, v.user(), source, target, recursive, v.keyfile())
    else:
        sys.stderr.write(f"Unknown type in {Pwngd.LOCKFILE}: {typ}\n")
        exit(1)


@app.command()
def clean():
    """
    clean current vagd instance (stop/kill/remove/destroy)
    """
    typ = _get_type()
    if typ == Dogd.TYPE:
        if os.path.exists(Dogd.LOCKFILE):
            with open(Dogd.LOCKFILE, 'r') as lockfile:
                data = lockfile.readline().split(':')
                id = data[0]
            import docker
            client = docker.from_env()
            if not client.containers.list(filters={'id': id}):
                sys.stderr.write(f'Lockfile {Dogd.LOCKFILE} found, container not running\n')
                exit(1)
            else:
                container = client.containers.get(id)
                typer.echo(f'Lockfile {Dogd.LOCKFILE} found, Docker Instance f{container.short_id}')
                container.kill()
        os.remove(Dogd.LOCKFILE)
        os.remove(Pwngd.LOCKFILE)
    elif typ == Qegd.TYPE:
        os.system("kill $(pgrep qemu)")
    elif typ == Vagd.TYPE:
        import vagrant
        v = vagrant.Vagrant(os.path.dirname(Vagd.VAGRANTFILE_PATH))
        v.halt()
        v.destroy()
        os.remove(Pwngd.LOCKFILE)
    else:
        sys.stderr.write(f"Unknown type in {Pwngd.LOCKFILE}: {typ}\n")
        exit(1)

def start():
    if pwn.term.term_mode:
        sys.stderr.write('wrong term mode')
        exit(2)
    app()
