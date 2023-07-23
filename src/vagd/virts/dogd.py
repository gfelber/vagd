import os
import pwn
import json
import docker

from vagd import templates, helper
from vagd.box import Box
from vagd.virts.shgd import Shgd
from vagd.virts.pwngd import Pwngd
from typing import Dict


class Dogd(Shgd):
    """
    | Docker virtualization for pwntools
    | SSH from cmd
    .. code-block:: bash

        ssh -o "StrictHostKeyChecking=no" -i ~/.vagd/keyfile -p $(cut .vagd/docker.lock -d":" -f 2) vagd@0.0.0.0

    | connect with docker exec
    .. code-block:: bash

       docker exec -it $(cut ./.vagd/docker.lock -d":" -f 1) /bin/bash

    | Kill from cmd:
    .. code-block:: bash

        docker kill $(cut ./.vagd/docker.lock -d":" -f 1)

    | Docker containers are automatically removed after they stop
    | Docker images need to be manually removed from docker
    | Dockerfiles are stored in home directory to allow caching ~/.vagd/docker/<image>/Dockerfile
    .. code-block:: bash

        docker images # list images
        docker rmi <id> # remove correct image
    """

    _image: str
    _user: str
    _port: int
    _client: docker.client
    _id: str
    _dockerdir: str
    _dockerfile: str
    _isalpine: bool
    _ex: bool
    _forward: Dict[str, int]

    DOCKERHOME = Pwngd.HOME_DIR + "docker/"
    DEFAULT_USER = 'vagd'
    DEFAULT_PORT = 2222
    DEFAULT_IMAGE = Box.DOCKER_FOCAL

    DEFAULT_PACKAGES = Pwngd.DEFAULT_PACKAGES + ["openssh-server"]
    LOCKFILE = Pwngd.LOCAL_DIR + 'docker.lock'

    def _create_dockerfile(self):

        pwn.log.info(f'create new Dockerfile at f{self._dockerfile}')
        if not os.path.exists(Pwngd.KEYFILE):
            helper.generate_keypair()

        if not os.path.exists(self._dockerdir + "keyfile.pub"):
            os.link(Pwngd.PUBKEYFILE, self._dockerdir + "keyfile.pub")
        template = templates.DOCKER_ALPINE_TEMPLATE if self._isalpine else templates.DOCKER_TEMPLATE

        with open(self._dockerfile, 'w') as dockerfile:
            dockerfile.write(
                template.format(image=self._image,
                                packages=' '.join(Dogd.DEFAULT_PACKAGES),
                                user=self._user,
                                keyfile=os.path.basename(self._dockerdir + "keyfile.pub")))

    def _create_docker_instance(self):
        pwn.log.info('starting docker instance')
        self._port = helper.first_free_port(Dogd.DEFAULT_PORT)
        self._forward.update({'22/tcp': self._port})
        if self._isalpine:
            self._forward.update({f'{Pwngd.STATIC_GDBSRV_PORT}/tcp': Pwngd.STATIC_GDBSRV_PORT})

        dir = os.path.dirname(os.path.realpath(__file__))
        with open(dir[:dir.rfind('/')] + '/res/seccomp.json', 'r') as seccomp_file:
            seccomp_rules = seccomp_file.read().strip()

        container = self._client.containers.run(self._bimage, ports=self._forward, detach=True, remove=True, security_opt=[f'seccomp:{seccomp_rules}'])
        self._id = container.id
        pwn.log.info(f'started docker instance {container.short_id}')
        with open(Dogd.LOCKFILE, 'w') as lockfile:
            lockfile.write(container.id + ':' + str(self._port))

    def _build_image(self):
        pwn.log.info('building docker image')
        return self._client.images.build(path=os.path.dirname(self._dockerfile), tag=f'vagd/{self._image}')[0]

    def _vm_create(self):

        if not os.path.exists(Pwngd.LOCAL_DIR):
            os.makedirs(Pwngd.LOCAL_DIR)

        if not os.path.exists(self._dockerfile):
            self._create_dockerfile()

        self._bimage = self._build_image()

        self._create_docker_instance()

    def _vm_setup(self) -> None:
        self._client = docker.from_env()
        if not os.path.exists(Dogd.LOCKFILE):
            pwn.log.info(f'No Lockfile {Dogd.LOCKFILE} found, creating new Docker Instance')
            self._vm_create()
        else:
            with open(Dogd.LOCKFILE, 'r') as lockfile:
                data = lockfile.readline().split(':')
                self._id = data[0]
                self._port = int(data[1])
            if not self._client.containers.list(filters={'id':self._id}):
                pwn.log.info(f'Lockfile {Dogd.LOCKFILE} found, container not running, creating new one')
                self._vm_create()
            else:
                pwn.log.info(
                    f'Lockfile {Dogd.LOCKFILE} found, Docker Instance f{self._client.containers.get(self._id).short_id}')

    def __init__(self,
                 binary: str,
                 image: str = DEFAULT_IMAGE,
                 user: str = DEFAULT_USER,
                 forward: Dict[str, int] = None,
                 ex: bool = False,
                 **kwargs):
        """

        :param binary: binary to execute
        :param image: docker base image
        :param user: name of user on docker container
        :param forward: Dictionary of forwarded ports, needs to follow docker api format: 'hostport/(tcp|udp)' : guestport
        :param ex: if experimental features, e.g. gdbserver should be enabled
        :param kwargs: parameters to pass through to super
        """

        self._image = image
        self._isalpine = 'alpine' in image
        self._dockerdir = Dogd.DOCKERHOME + f'{self._image}/'
        if not (os.path.exists(Dogd.DOCKERHOME) and os.path.exists(self._dockerdir)):
            os.makedirs(self._dockerdir)
        self._dockerfile = self._dockerdir + 'Dockerfile'
        self._user = user
        self._forward = forward
        self._ex = ex
        if self._isalpine and not self._ex:
            pwn.log.error("Docker alpine images requires experimental features")
        if self._forward is None:
           self._forward = dict()

        self._vm_setup()

        gdbsrvport = Pwngd.STATIC_GDBSRV_PORT if self._isalpine else None
        super().__init__(binary=binary,
                         user=self._user,
                         port=self._port,
                         ex=ex,
                         gdbsrvport=gdbsrvport,
                         **kwargs)
