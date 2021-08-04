import docker
from wazuh_testing.qa_ctl.deployment.Instance import Instance
from json import dumps


class DockerWrapper(Instance):
    """Class to handle docker operations. This class uses the docker python SDK to read a dockerfile and create
       the image and container.

       Attributes:
        dockerfile_path (str): Path where the Dockerfile is stored.
        name (str): Container's name.
        remove (bool): Remove the container after it has finished.
        detach (bool): Run container in background.
        ports (dict): Ports to bind inside the container.
                      The keys of the dictionary are the ports to bind inside the container and the values of the
                      dictionary are the corresponding ports to open on the host.
        stdout (bool): Return stdout logs when detach is False.
        stderr (bool): Return stderr logs when detach is False.

       Args:
        dockerfile_path (str): Value to set dockerfile_path attribute.
        name (str): Value to set name attribute.
        remove (bool): Value to set remove attribute.
        detach (bool): Value to set detach attribute.
        ports (dict): Value to set ports attribute.
        stdout (bool): Value to set stdout attribute.
        stderr (bool): Value to set stderr attribute.
    """
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
        """Function to get the container using the name attribute:

        Returns:
            Container: Container object with the container info.

        Raises:
            docker.errors.NotFound: If the container does not exist.
            docker.errors.APIError: If the server returns an error.
        """
        return self.docker_client.containers.get(self.name)

    def run(self):
        self.docker_client.containers.run(image=self.image, name=self.name, ports=self.ports,
                                          remove=self.remove, detach=self.detach, stdout=self.stdout,
                                          stderr=self.stderr)

    def restart(self):
        """Restart the container.
        Raises:
            docker.errors.APIError: If the server returns an error.
        """
        self.get_container().restart()

    def halt(self):
        """Stops the container.
        Raises:
            docker.errors.APIError: If the server returns an error.
        """
        self.get_container().stop()

    def destroy(self, remove_image=False):
        """Removes the container
        Args:
            remove_image(bool): Remove the docker image too. Defaults to False.
        Raises:
            docker.errors.APIError: If the server returns an error.
        """
        self.get_container().remove()
        if remove_image:
            self.docker_client.images.remove(image=self.image.id, force=True)

    def get_instance_info(self):
        """Get the parameters information.
        Returns
            str: String in JSON format with the parameters of the class.
        """
        api_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        docker_info = api_client.inspect_container(self.name)

        return dumps({'name': self.name, 'parameters': {
            'dockerfile_path': self.dockerfile_path, 'remove': self.remove,
            'ip': docker_info['NetworkSettings']['IPAddress'],
            'detach': self.detach, 'ports': self.ports, 'stderr': self.stderr,
            'stdout': self.stdout}
        })

    def get_name(self):
        """Get the name of the container.
        Returns
            str: String with the name of the container.
        """
        return self.name

    def status(self):
        """Get the status of the container.
        Returns:
            str: String with the status of the container (running, exited, not created, etc).
        """
        try:
            status = self.get_container().status
        except docker.errors.NotFound:
            status = 'not_created'
        return status
