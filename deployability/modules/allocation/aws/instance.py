import boto3

from pathlib import Path
from modules.allocation.generic import Instance
from modules.allocation.generic.models import ConnectionInfo
from modules.allocation.generic.utils import logger
from .credentials import AWSCredentials


class AWSInstance(Instance):
    """
    AWSInstance class for managing an individual AWS EC2 instance.
    It inherits from the generic Instance class.

    Attributes:
        path (str or Path): Directory where instance data is stored.
        identifier (str): Identifier of the instance.
        credentials (AWSCredentials): AWS credentials object.
        user (str): User associated with the instance.
    """

    def __init__(self, path: str | Path, identifier: str, credentials: AWSCredentials = None, user: str = None) -> None:
        """
        Initialize an AWSInstance object.

        Args:
            path (str or Path): Directory where instance data is stored.
            identifier (str): Identifier of the instance.
            credentials (AWSCredentials): AWS credentials object.
            user (str): User associated with the instance.
        """
        super().__init__(path, identifier, credentials)
        self._user = user
        self._client = boto3.resource('ec2')
        self._instance = self._client.Instance(self.identifier)
        if not self.credentials:
            logger.debug(f"No credentials found. Loading from instance directory.")
            self.credentials = self.__get_credentials()

    def start(self) -> None:
        """Start the AWS EC2 instance."""
        self._instance.start()
        self._instance.wait_until_running()

    def reload(self) -> None:
        """Reboot the AWS EC2 instance."""
        self._instance.reboot()

    def stop(self) -> None:
        """Stop the AWS EC2 instance."""
        self._instance.stop()
        self._instance.wait_until_stopped()

    def delete(self) -> None:
        """Terminate and delete the AWS EC2 instance."""
        self._instance.terminate()
        self._instance.wait_until_terminated()

    def status(self) -> str:
        """Get the status of the AWS EC2 instance."""
        return self._instance.state

    def ssh_connection_info(self) -> ConnectionInfo:
        """
        Get connection information for SSH.

        Returns:
            ConnectionInfo: SSH connection information.
        """
        return ConnectionInfo(hostname=self._instance.public_dns_name,
                              user=self._user,
                              port=22,
                              private_key=str(self.credentials.key_path))

    def __get_credentials(self) -> AWSCredentials:
        """
        Get AWS credentials associated with the instance.

        Returns:
            AWSCredentials: Loaded AWS credentials.
        """
        key_name = self._instance.key_name
        credentials = AWSCredentials()
        credentials.load(key_name)
        return credentials
