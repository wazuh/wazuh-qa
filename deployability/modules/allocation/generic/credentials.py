# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from abc import ABC, abstractmethod
from pathlib import Path


class Credentials(ABC):
    """
    An abstract base class for credentials.

    This class provides an interface for generating, loading, and deleting credentials key pairs.

    Attributes:
        name (str): The name of the credentials.
        key_path (Path): The path of the key.
        key_id (str): The id of the key.
    """

    class CredentialsError(Exception):
        """
        Exception raised for errors in the key creation process.
        """
        pass

    def __init__(self) -> None:
        """
        Initializes a Credentials object.
        """
        self.name: str = None
        self.key_path: Path = None
        self.key_id: str = None

    @abstractmethod
    def generate(self, **kwargs) -> Path:
        """
        Abstract method that generates a credentials key pair.

        Returns:
            Path: The path of the generated key pair.
        """
        pass

    @abstractmethod
    def load(self, **kwargs) -> Path:
        """
        Abstract method that loads a credentials key pair.

        Returns:
            Path: The path of the loaded key pair.
        """
        pass

    @abstractmethod
    def delete(self, **kwargs) -> None:
        """
        Abstract method that deletes a credentials key pair.
        """
        pass
