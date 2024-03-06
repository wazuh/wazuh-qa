from abc import ABC, abstractmethod
from pathlib import Path
from .utils import logger

from .credentials import Credentials
from .models import ConnectionInfo


class Instance(ABC):
    """
    An abstract base class for instances.

    This class provides an interface for starting, reloading, stopping, deleting, and getting the status of instances.
    It also provides a method to get SSH connection information for the instance.

    Attributes:
        path (Path): The path of the instance.
        identifier (str): The identifier of the instance.
        credentials (Credentials): The credentials of the instance.
    """

    def __init__(self, path: str | Path, identifier: str, platform: str, credentials: Credentials = None, host_identifier: str = None, host_instance_dir: str | Path = None, macos_host_parameters: dict = None, arch: str = None, ssh_port: str = None, user: str = None) -> None:
        """
        Initializes an Instance object.

        Args:
            path (str | Path): The path of the instance.
            identifier (str): The identifier of the instance.
            platform (str): The platform of the instance.
            credentials (VagrantCredentials, optional): The credentials of the instance. Defaults to None.
            host_identifier (str, optional): The host for the instance. Defaults to None.
            host_instance_dir (str | Path, optional): The remote directory of the instance. Defaults to None.
            macos_host_parameters (dict, optional): The parameters of the remote host. Defaults to None.
            arch (str, optional): The architecture of the instance. Defaults to None.
            ssh_port (str, optional): The SSH port of the instance. Defaults to None.
            user (str): User associated with the instance.

        Raises:
            ValueError: If the path does not exist or is not a directory.
            ValueError: If the credentials are not a subclass of Credentials.
        """
        path = Path(path)
        if not path.exists() or not path.is_dir():
            logger.error(f"Invalid instance path: {path}")
            exit(1)
        if credentials and not issubclass(type(credentials), Credentials):
            logger.error(f"Invalid credentials: {credentials}")
            exit(1)

        self.path: Path = path
        self.identifier: str = str(identifier)
        self.credentials: Credentials = credentials
        self.host_identifier: str = host_identifier
        self.host_instance_dir: Path = host_instance_dir
        self.ssh_port: str = ssh_port
        self.macos_host_parameters: dict = macos_host_parameters
        self.platform: str = platform
        self.arch: str = arch
        self.user: str = user

    @abstractmethod
    def start(self) -> None:
        """
        Abstract method that starts the instance.
        """
        pass

    @abstractmethod
    def reload(self) -> None:
        """
        Abstract method that reloads the instance.
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        Abstract method that stops the instance.
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Abstract method that deletes the instance.
        """
        pass

    @abstractmethod
    def status(self) -> str:
        """
        Abstract method that returns the status of the instance.

        Returns:
            str: The status of the instance.
        """
        pass

    @abstractmethod
    def ssh_connection_info(self) -> ConnectionInfo:
        """
        Abstract method that returns the SSH connection information for the instance.

        Returns:
            ConnectionInfo: The SSH connection information for the instance.
        """
        pass
