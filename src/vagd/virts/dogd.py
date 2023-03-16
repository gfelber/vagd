import os
import docker

from vagd.virts.shgd import Shgd
from vagd.virts.pwngd import Pwngd
from vagd.box import Box

class Dogd(Shgd):
    """ Docker virtualization for pwntools """

    _image: str
    _dockerfile: str
    _client: docker.client

    DEFAULT_PACKAGES = Pwngd.DEFAULT_PACKAGES + ["ssh"]
    DEFAULT_DOCKERFILE = Pwngd.LOCAL_DIR + "Dockerfile"
    LOCKFILE = Pwngd.LOCAL_DIR + 'docker.lock'

    def _create_dockerfile(self):
        if not os.path.exists(Pwngd.KEYFILE):
            helper.generate_keypair()

        with open(Pwngd.KEYFILE + '.pub') as pubkeyfile:
            pubkey = pubkeyfile.readline()

        with open(Dogd.DEFAULT_DOCKERFILE, 'w') as dockerfile:
            dockerfile.write(
                templates.DOCKER_TEMPLATE.format(image=self._image, packages=Dogd.DEFAULT_PACKAGES, pubkey=pubkey))

    def _create_docker_instance(self):
        container = self._client.containers.run(Dogd.LOCKFILE, detach=True)
        with open(Dogd.LOCKFILE, 'w') as lockfile:
            lockfile.write(container.id)

    def _vm_setup(self) -> None:
        self._client = docker.from_env()

        if self._dockerfile == Dogd.DEFAULT_DOCKERFILE and not os.path.exists(self._dockerfile):
            self._create_dockerfile()

        if not os.path.exists(Dogd.LOCKFILE):
            self._create_docker_instance()

    def __init__(self,
                binary: str,
                image: str = Box.DOCKER_FOCAL,
                dockerfile: str = DEFAULT_DOCKERFILE,
                **kwargs):
        self._image = image
        self._dockerfile = dockerfile

        self._vm_setup()

        super().__init__(binary=binary, **kwargs)
