# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from abc import ABC, abstractmethod
from pathlib import Path

from .credentials import Credentials
from .models import ConnectionInfo, InstancePayload


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

    def __init__(self, instance_parameters: InstancePayload, credentials: Credentials = None) -> None:
        """
        Initializes an Instance object.

        Args:
            instance_parameters (InstancePayload): The parameters of the instance.
            credentials (Credentials, optional): The credentials of the instance. Defaults to None.

        Raises:
            ValueError: If the path does not exist or is not a directory.
            ValueError: If the credentials are not a subclass of Credentials.
        """
        path = Path(instance_parameters.instance_dir)
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Invalid instance path: {path}")
        if credentials and not issubclass(type(credentials), Credentials):
            raise ValueError(f"Invalid credentials: {credentials}")

        self.path: Path = path
        self.identifier: str = str(instance_parameters.identifier)
        self.name: str = instance_parameters.name
        self.credentials: Credentials = credentials
        self.host_identifier: str = instance_parameters.host_identifier
        self.host_instance_dir: Path = instance_parameters.host_instance_dir
        self.ssh_port: str = instance_parameters.ssh_port
        self.remote_host_parameters: dict = instance_parameters.remote_host_parameters
        self.platform: str = instance_parameters.platform
        self.arch: str = instance_parameters.arch
        self.user: str = instance_parameters.user
        self.virtualizer: str = instance_parameters.virtualizer

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
