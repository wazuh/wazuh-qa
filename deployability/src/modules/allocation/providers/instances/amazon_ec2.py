import os
import re
import boto3
import subprocess

from pathlib import Path

from .generic import ConnectionInfo, Instance, ProviderConfig


class AmazonEC2Config(ProviderConfig):
    id: str
    type: str
    ami: str
    region: str
    user: str


class AmazonEC2Instance(Instance):

    def __init__(self, base_dir: str | Path, name: str, identifier: str, user: str, key_pair: str | Path = None) -> None:
        self._user = user
        self._client = boto3.resource('ec2')
        self._instance = self._client.Instance(identifier)

        super().__init__(base_dir, name, identifier, key_pair)
        if not self.key_pair:
            self.key_pair = self.__get_key_pair()

    def start(self) -> None:
        self._instance.start()
        self._instance.wait_until_running()

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
                              private_key=self.key_path)

    def __get_key_pair(self):
        key_path = Path(self.path, self._instance.key_pair).with_suffix(".pem")
        with open(key_path, 'w') as key_file:
            key_file.write(self._instance.key_pair.key_material)
            os.chmod(key_path, 0o600)
        return key_path
