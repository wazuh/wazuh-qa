from os import remove
import docker
from Instance import Instance


class DockerWrapper(Instance):
    def __init__(self, dockerfile_path, name, remove, ports=None, detach=True, stdout=False, stderr=False):
        self.docker_client = docker.from_env()
        self.dockerfile_path = dockerfile_path
        self.name = name
        self.remove = remove
        self.detach = detach
        self.ports = ports

        if self.detach:
            self.stdout = stdout
            self.stderr = stderr
        else:
            self.stdout = True
            self.stderr = True

        self.image = self.docker_client.images.build(path=self.dockerfile_path)[0]


    def get_container(self):
        return self.docker_client.containers.get(self.name)


    def run(self):
        try:
            existing_container = self.docker_client.containers.get(self.name)
            existing_container.start()

        except docker.errors.NotFound:
            self.docker_client.containers.run(image=self.image, name=self.name, ports=self.ports,
                                              remove=self.remove, detach=self.detach, stdout=self.stdout,
                                              stderr=self.stderr)

    def restart(self):
        self.get_container().restart()


    def halt(self):
        self.get_container().stop()


    def destroy(self, remove_image=False):
        self.get_container().remove()
        if remove_image:
            self.docker_client.images.remove(image=self.image.id, force=True)


    def get_instance_info(self):
        return self.parameters


    def get_name(self):
        return self.name

    def status(self):
        try:
            status = self.get_container().status
        except docker.errors.NotFound:
            status = 'Not created'
        return status
