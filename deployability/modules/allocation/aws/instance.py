import boto3

from pathlib import Path

from modules.allocation.generic import Instance
from modules.allocation.generic.models import ConnectionInfo
from .credentials import AWSCredentials


class AWSInstance(Instance):

    def __init__(self, path: str | Path, identifier: str, credentials: AWSCredentials = None, user: str = None) -> None:
        super().__init__(path, identifier, credentials)
        self._user = user
        self._client = boto3.resource('ec2')
        self._instance = self._client.Instance(self.identifier)
        if not self.credentials:
            self.credentials = self.__get_credentials()

    def start(self) -> None:
        self._instance.start()
        self._instance.wait_until_running()

    def reload(self) -> None:
        self._instance.reboot()

    def stop(self) -> None:
        self._instance.stop()
        self._instance.wait_until_stopped()

    def delete(self) -> None:
        self._instance.terminate()
        self._instance.wait_until_terminated()

    def status(self) -> str:
        return self._instance.state

    def ssh_connection_info(self) -> ConnectionInfo:
        return ConnectionInfo(hostname=self._instance.public_dns_name,
                              user=self._user,
                              port=22,
                              private_key=self.credentials.key_path)

    def __get_credentials(self) -> AWSCredentials:
        key_name = self._instance.key_name
        credentials = AWSCredentials()
        credentials.load(self.path, key_name)
        return credentials
