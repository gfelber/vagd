import importlib.metadata
import os
import stat
import sys
from typing import Optional, Dict, List

import typer
from rich.console import Console
from rich.syntax import Syntax

from vagd import helper
# prevents term.init
from vagd.virts.dogd import Dogd
from vagd.virts.pwngd import Pwngd
from vagd.virts.qegd import Qegd
from vagd.virts.vagd import Vagd

DOGD_BOX = "Box.DOCKER_JAMMY"
DOGD = "vm = Dogd(BINARY, image={box}, {args})  # Docker"
QEGD_BOX = "Box.QEMU_JAMMY"
QEGD = "vm = Qegd(BINARY, img={box}, {args})  # Qemu"
SHGD = "vm = Shgd(BINARY, user='user', host='localhost', port=22, {args})  # SSH"

# deprecated
VAGD_BOX = "Box.VAGRANT_JAMMY64"
VAGD = "vm = Vagd(BINARY, {box}, {args})  # Vagrant"

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]})

err_console = Console(stderr=True)
console = Console()


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


def add_virt(dependencies: List[str],
             vms: List[str],
             dependency: str,
             template: str,
             args: Dict[str, str],
             multi=False,
             box=''):

    dependencies.append(dependency)
    args_str = ', '.join(f'{k}={v}' for k, v in args.items())
    vm = template.format(box=box, args=args_str)
    vms.append(('# ' if multi else '') + vm)


@app.command()
def template(
        binary: Optional[str] = typer.Argument('', help='Binary to Exploit'),
        ip: Optional[str] = typer.Argument('', help='Ip or Domain of the remote target'),
        port: Optional[int] = typer.Argument(0, help='port of the remote target'),
        output_exploit: Optional[bool] = typer.Option(False, '-e',
                                                      help='output file of the template (also add +x) to exploit.py'),
        output: Optional[str] = typer.Option('', '-o',
                                             help='output file of the template (also add +x), default stdout'),
        libc: Optional[str] = typer.Option('', '--libc', '-l', help='add libc to template'),
        libs: Optional[bool] = typer.Option(False, '--libs', help='download libraries from virt'),
        files: Optional[List[str]] = typer.Option([], '--files', '-f', help='add files to remote'),
        aslr: Optional[bool] = typer.Option(False, '--aslr', '-a', help='enable gdb ASLR (default: disabled for gdb)'),
        dogd: Optional[bool] = typer.Option(False, '--dogd', '--docker', '-d', help='create docker template'),
        image: Optional[str] = typer.Option(DOGD_BOX, '--image', help='docker image to use'),
        qegd: Optional[bool] = typer.Option(False, '--qegd', '--qemu', '-q', help='create qemu template'),
        img: Optional[str] = typer.Option(QEGD_BOX, '--img', help='qemu cloud image to use'),
        vagd: Optional[bool] = typer.Option(False, '--vagd', '--vagrant', help='DEPRECATED: create vagrant template'),
        vbox: Optional[str] = typer.Option(VAGD_BOX, '--vbox', help='vagrant box to use'),
        shgd: Optional[bool] = typer.Option(False, '--shgd', '--ssh', '-s', help='create ssh template'),
        local: Optional[bool] = typer.Option(False, '--local', help='create local template'),
):
    """
    creates a template
    """

    if image != DOGD_BOX:
        dogd = True
        image = f"'{image}'"

    if img != QEGD_BOX:
        qegd = True
        img = f"'{img}'"

    if vbox != VAGD_BOX:
        vagd = True
        vbox = f"'{vbox}'"

    templatePath = os.path.dirname(os.path.realpath(__file__))
    templateChunks = []
    aliasesPath = templatePath + "/res/aliases.txt"
    templatePath += '/res/template.txt'
    multi = False
    if not any((dogd, qegd, vagd, shgd)):
        dogd = qegd = True

    if sum((dogd, qegd, vagd, shgd)) > 1:
        multi = True


    env = {}
    if libc:
        files.append(libc)
        env['LD_PRELOAD'] = os.path.basename(libc)

    dependencies = []
    vms = []
    args = dict()

    if libs:
        args['libs'] = True

    if files:
        args['files'] = '[' + ','.join(f"'{file}'" for file in files) + ']'

    args['ex'] = 'True'
    args['fast'] = 'True'

    if dogd:
        add_virt(dependencies, vms, 'Dogd', DOGD, args, box=image)
    if qegd:
        add_virt(dependencies, vms, 'Qegd', QEGD, args, multi, box=img)
    if vagd:
        add_virt(dependencies, vms, 'Vagd', VAGD, args, multi, box=vbox)
    if shgd:
        add_virt(dependencies, vms, 'Shgd', SHGD, args, multi)

    with open(aliasesPath, 'r') as aliases_file:
        aliases = aliases_file.read()


    if libc and libs:
        err_console.print("using --libs and --libc, uncomment libc after init")

    with (open(templatePath, 'r') as templateFile):
        for line in templateFile.readlines():

            if libc and not libs and line.startswith('# libc'):
                templateChunks.append(line[2:])
            else:
                templateChunks.append(line)

        template = ''.join(templateChunks).format('{}',
                                                  aliases=aliases,
                                                  binary=binary,
                                                  ip=ip,
                                                  port=str(port),
                                                  env=env,
                                                  libc=libc,
                                                  aslr=aslr,
                                                  is_local=True if local else 'args.LOCAL',
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
            syntax = Syntax(template, 'python', theme='ansi_dark')
            console.print(syntax)


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
        os.remove(Vagd.VAGRANTFILE_PATH)
    else:
        sys.stderr.write(f"Unknown type in {Pwngd.LOCKFILE}: {typ}\n")
        exit(1)
    os.remove(Pwngd.LOCKFILE)


def start():
    app()
