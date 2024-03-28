import importlib.metadata
import os
import stat
import sys
from typing import Optional, Dict, List

import typer

from vagd import helper
# prevents term.init
from vagd.virts.dogd import Dogd
from vagd.virts.pwngd import Pwngd
from vagd.virts.qegd import Qegd
from vagd.virts.vagd import Vagd

DOGD = "vm = Dogd(exe.path, image=Box.DOCKER_JAMMY, ex=True, fast=True{files})  # Docker"
QEGD = "vm = Qegd(exe.path, img=Box.QEMU_JAMMY, ex=True, fast=True{files})  # Qemu"
SHGD = "vm = Shgd(exe.path, user='user', host='localhost', port=22, ex=True, fast=True{files})  # SSH"

# deprecated
VAGD = "vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, ex=True, fast=True{files})  # Vagrant"

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

def add_virt(dependencies:List[str], vms:List[str], dependency:str, template:str, files:List[str], multi=False):
    files_str = '' if len(files) == 0 else ', files=[\''
    files_str += '\', \''.join(files)
    files_str += '' if len(files) == 0 else '\']'

    dependencies.append(dependency)
    vms.append(('# ' if multi else '') + template.format(files=files_str))

@app.command()
def template(
        binary: Optional[str] = typer.Argument('', help='Binary to Exploit'),
        ip: Optional[str] = typer.Argument('', help='Ip or Domain of the remote target'),
        port: Optional[int] = typer.Argument(0, help='port of the remote target'),
        output_exploit: Optional[bool] = typer.Option(False, '-e', help='output file of the template (also add +x) to exploit.py'),
        output: Optional[str] = typer.Option('', '-o', help='output file of the template (also add +x), default stdout'),
        libc: Optional[str] = typer.Option('', '--libc', '-l', help='add libc to template'),
        files: Optional[List[str]] = typer.Option([], '--files', '-f', help='add files to remote'),
        aslr: Optional[bool] = typer.Option(False, '--aslr', '-a', help='enable gdb ASLR (default: disabled for gdb)'),
        dogd: Optional[bool] = typer.Option(False, '--dogd', '--docker', '-d', help='create docker template'),
        qegd: Optional[bool] = typer.Option(False, '--qegd', '--qemu', '-q', help='create qemu template'),
        vagd: Optional[bool] = typer.Option(False, '--vagd', '--vagrant', help='DEPRECATED: create vagrant template'),
        shgd: Optional[bool] = typer.Option(False, '--shgd', '--ssh', '-s', help='create ssh template'),
        local: Optional[bool] = typer.Option(False, '--local', help='create local template'),
):
    """
    creates a template
    """
    templatePath = os.path.dirname(os.path.realpath(__file__))
    templateChunks = []
    aliasesPath = templatePath + "/res/aliases.txt"
    templatePath += '/res/local_template.txt' if local else '/res/template.txt'
    multi = False
    if not any((dogd, qegd, vagd, shgd)):
        dogd = qegd = shgd = True
        multi = True

    if libc:
        files.append(libc)

    dependencies = []
    vms = []
    if dogd:
        add_virt(dependencies, vms, 'Dogd', DOGD, files)
    if qegd:
        add_virt(dependencies, vms, 'Qegd', QEGD, files, multi)
    if vagd:
        add_virt(dependencies, vms, 'Vagd', VAGD, files, multi)
    if shgd:
        add_virt(dependencies, vms, 'Shgd', SHGD, files, multi)

    with open(aliasesPath, 'r') as aliases_file:
        aliases = aliases_file.read()

    with open(templatePath, 'r') as templateFile:
        for line in templateFile.readlines():

            if libc and line.startswith('# libc'):
                templateChunks.append(line[2:])
            else:
                templateChunks.append(line)

        template = ''.join(templateChunks).format('{}',
                                                  aliases=aliases,
                                                  binary=binary,
                                                  ip=ip,
                                                  port=str(port),
                                                  libc=libc,
                                                  aslr=aslr,
                                                  dependencies=', '.join(dependencies),
                                                  vms=('\n' + ' ' * 4).join(vms))

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
    import pwn
    elf = pwn.ELF(binary)
    helper.info(elf.section('.comment').decode().replace('\0', '\n'))


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
    elif typ == Qegd.TYPE:
        os.system("kill $(pgrep qemu)")
    elif typ == Vagd.TYPE:
        import vagrant
        v = vagrant.Vagrant(os.path.dirname(Vagd.VAGRANTFILE_PATH))
        v.halt()
        v.destroy()
    else:
        sys.stderr.write(f"Unknown type in {Pwngd.LOCKFILE}: {typ}\n")
        exit(1)
    os.remove(Pwngd.LOCKFILE)

def start():
    app()
