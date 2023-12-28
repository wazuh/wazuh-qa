import os
import re
import boto3
import subprocess

from pathlib import Path

from .generic import ConnectionInfo, Instance
from ..credentials.amazon_ec2 import AWSCredentials


# class AmazonEC2Config(ProviderConfig):
#     id: str
#     type: str
#     ami: str
#     zone: str
#     user: str


class AmazonEC2Instance(Instance):

    def __init__(self, base_dir: str | Path, identifier: str, user: str, credentials: AWSCredentials = None) -> None:
        self._user = user
        self._client = boto3.resource('ec2')
        self._instance = self._client.Instance(identifier)

        super().__init__(base_dir, identifier, credentials)
        if not self.credentials:
            self.credentials = self.__get_credentials()

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
                              private_key=self.credentials.key_path)

    def __get_credentials(self) -> AWSCredentials:
        key_name = self._instance.key_name
        credentials = AWSCredentials()
        credentials.load(self.path, key_name)
        return credentials
