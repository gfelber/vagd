import os
import pwn
import docker

from vagd import templates, helper
from vagd.box import Box
from vagd.virts.shgd import Shgd
from vagd.virts.pwngd import Pwngd


class Dogd(Shgd):
    """
    | Docker virtualization for pwntools
    | SSH from cmd
    .. code-block:: bash

        ssh -o "StrictHostKeyChecking=no" -i .vagd/keyfile -p $(cut .vagd/docker.lock -d":" -f 2) vagd@0.0.0.0

    | connect with docker exec
    .. code-block:: bash

       docker exec -it $(cut ./.vagd/docker.lock -d":" -f 1) /bin/bash

    | Kill from cmd:
    .. code-block:: bash

        docker kill $(cut ./.vagd/docker.lock -d":" -f 1)

    | Docker containers are automatically removed after they stop
    | Docker images need to be manually removed from docker
    .. code-block:: bash

        docker images # list images
        docker rmi <id> # remove correct image
    """

    _image: str
    _user: str
    _port: int
    _client: docker.client
    _id: str

    DEFAULT_USER = 'vagd'
    DEFAULT_PORT = 2222
    DEFAULT_IMAGE = Box.DOCKER_FOCAL

    DEFAULT_PACKAGES = Pwngd.DEFAULT_PACKAGES + ["openssh-server"]
    DEFAULT_DOCKERFILE = Pwngd.LOCAL_DIR + "Dockerfile"
    LOCKFILE = Pwngd.LOCAL_DIR + 'docker.lock'

    def _create_dockerfile(self):

        pwn.log.info(f'create new Dockerfile at f{self._dockerfile}')
        if not os.path.exists(Pwngd.KEYFILE):
            helper.generate_keypair()

        with open(Dogd.DEFAULT_DOCKERFILE, 'w') as dockerfile:
            dockerfile.write(
                templates.DOCKER_TEMPLATE.format(image=self._image,
                                                 packages=' '.join(Dogd.DEFAULT_PACKAGES),
                                                 user=self._user,
                                                 keyfile=os.path.basename(Pwngd.KEYFILE + '.pub')))

    def _create_docker_instance(self):
        pwn.log.info('starting docker instance')
        self._port = helper.first_free_port(Dogd.DEFAULT_PORT)
        container = self._client.containers.run(self._bimage, ports={'22/tcp': self._port}, detach=True, remove=True)
        self._id = container.id
        pwn.log.info(f'started docker instance {container.short_id}')
        with open(Dogd.LOCKFILE, 'w') as lockfile:
            lockfile.write(container.id + ':' + str(self._port))

    def _build_image(self):
        pwn.log.info('building docker image')
        return self._client.images.build(path=os.path.dirname(self._dockerfile))[0]

    def _vm_create(self):

        if self._dockerfile == Dogd.DEFAULT_DOCKERFILE and not os.path.exists(self._dockerfile):
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
            if not helper.is_port_in_use(self._port):
                pwn.log.info(f'Lockfile {Dogd.LOCKFILE} found, port not used, creating new container')
                self._vm_create()
            else:
                pwn.log.info(
                    f'Lockfile {Dogd.LOCKFILE} found, Docker Instance f{self._client.containers.get(self._id).short_id}')

    def __init__(self,
                 binary: str,
                 image: str = DEFAULT_IMAGE,
                 user: str = DEFAULT_USER,
                 **kwargs):
        """

        :param binary: binary to execute
        :param image: docker base image
        :param user: name of user on docker container
        :param kwargs: parameters to pass through to super
        """
        self._image = image
        self._dockerfile = Dogd.DEFAULT_DOCKERFILE
        self._user = user

        self._vm_setup()

        super().__init__(binary=binary,
                         user=self._user,
                         port=self._port,
                         **kwargs)
