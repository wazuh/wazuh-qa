# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import shutil
import uuid
import yaml
import re

from abc import ABC, abstractmethod
from pathlib import Path

from .instance import Instance
from .models import CreationPayload, ProviderConfig, InstancePayload
from .utils import logger


class Provider(ABC):
    """
    An abstract base class for providers.

    This class provides an interface for creating, loading, and destroying instances.
    It also provides methods to get OS, size, and miscellaneous specifications for the provider.

    Attributes:
        provider_name (str): The name of the provider.
    """

    # Paths to the templates and specs directories.
    ROOT_DIR = Path(__file__).parent.parent / 'static'
    TEMPLATES_DIR = ROOT_DIR / 'templates'
    SPECS_DIR = ROOT_DIR / 'specs'
    OS_PATH = SPECS_DIR / 'os.yml'
    SIZE_PATH = SPECS_DIR / 'size.yml'
    MISC_PATH = SPECS_DIR / 'misc.yml'


    class ProvisioningError(Exception):
        """
        Exception raised for errors in the provisioning process.
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Abstract property that should return the name of the provider.

        Returns:
            str: The name of the provider.
        """
        pass

    @classmethod
    def create_instance(cls, base_dir: str | Path, params: CreationPayload, config: ProviderConfig = None, ssh_key: str = None) -> Instance:
        """
        Creates a new instance.

        Args:
            base_dir (str | Path): The base directory for the instance.
            params (CreationPayload): The parameters for creating the instance.
            config (ProviderConfig, optional): The configuration for the instance. Defaults to None.
            ssh_key (str, optional): Public or private key for the instance. For example, we assume that if the public key is provided, the private key is located in the same directory and has the same name as the public key. Defaults to None.

        Returns:
            Instance: The created instance.
        """
        params = CreationPayload(**dict(params))
        base_dir = Path(base_dir)
        return cls._create_instance(base_dir, params, config, ssh_key)

    @classmethod
    def load_instance(cls, instance_dir: str | Path, instance_id: str) -> Instance:
        """
        Loads an existing instance.

        Args:
            instance_dir (str | Path): The directory of the instance.
            instance_id (str): The id of the instance.

        Returns:
            Instance: The loaded instance.

        Raises:
            ValueError: If the instance directory does not exist.
        """
        instance_dir = Path(instance_dir)
        if not instance_dir.exists():
            raise ValueError(f"Instance path {instance_dir} does not exist")
        return cls._load_instance(instance_dir, instance_id)

    @classmethod
    def destroy_instance(cls, destroy_parameters: InstancePayload) -> None:
        """
        Destroys an existing instance and removes its directory.

        Args:
            destroy_parameters (InstancePayload): The parameters for destroying the instance.
        """
        destroy_parameters.instance_dir = Path(destroy_parameters.instance_dir)
        cls._destroy_instance(destroy_parameters)
        shutil.rmtree(destroy_parameters.instance_dir, ignore_errors=True)

    @classmethod
    @abstractmethod
    def _create_instance(cls, base_dir: Path, params: CreationPayload, config: ProviderConfig = None, ssh_key: str = None) -> Instance:
        """
        Abstract method that creates a new instance.

        Args:
            base_dir (Path): The base directory for the instance.
            params (CreationPayload): The parameters for creating the instance.
            config (ProviderConfig, optional): The configuration for the instance. Defaults to None.
            ssh_key (str, optional): Public or private key for the instance. Defaults to None.

        Returns:
            Instance: The created instance.
        """
        pass

    @classmethod
    @abstractmethod
    def _load_instance(cls, instance_dir: Path, identifier: str) -> Instance:
        """
        Abstract method that loads an existing instance.

        Args:
            instance_dir (Path): The directory of the instance.
            identifier (str): The identifier of the instance.

        Returns:
            Instance: The loaded instance.
        """
        pass

    @classmethod
    @abstractmethod
    def _destroy_instance(cls, destroy_parameters: InstancePayload) -> None:
        """
        Abstract method that destroys an existing instance.

        Args:
            destroy_parameters (InstancePayload): The parameters for destroying the instance.
        """
        pass

    @staticmethod
    def _generate_instance_id(prefix: str) -> str:
        """
        Generates a random instance id with the given prefix.

        Args:
            prefix (str): The prefix for the instance id.

        Returns:
            str: The instance id.
        """
        return f"{prefix}-{uuid.uuid4()}".upper()

    @classmethod
    def _get_os_specs(cls, composite_name: str) -> dict:
        """
        Gets the OS specifications for the provider.
        composite_name (str): The name of the composite OS.

        Returns:
            dict: A dictionary containing the OS specifications for the provider.
        """
        with open(cls.OS_PATH, "r") as f:
            version_available = []
            os_list = yaml.safe_load(f).get(cls.provider_name)
            for os in os_list:
                if os.split("-")[1] == composite_name.split("-")[1]:
                    version_available.append(os)
                if str(os) == composite_name:
                    return os_list[os]

            raise ValueError(f"OS {composite_name} not available for provider {cls.provider_name}. Available versions are {version_available}")

    @classmethod
    def _get_size_specs(cls, size: str) -> dict:
        """
        Gets the size specifications for the provider.
        size (str): The name of the size.

        Returns:
            dict: A dictionary containing the size specifications for the provider.
        """
        with open(cls.SIZE_PATH, "r") as f:
            size_list = yaml.safe_load(f).get(cls.provider_name)
            for s in size_list:
                if size == s:
                    return size_list[s]

    @classmethod
    def _get_misc_specs(cls) -> dict:
        """
        Gets the miscellaneous specifications for the provider.

        Returns:
            dict: A dictionary containing the miscellaneous specifications for the provider.
        """
        with open(cls.MISC_PATH, "r") as f:
            return yaml.safe_load(f).get(cls.provider_name)

    @staticmethod
    def generate_repository_name(repository: str) -> str:
        """
        Generate a repository name for the instance.

        Args:
            repository (str): Repository name.

        Returns:
            str: Repository name for the instance.
        """
        matches = re.findall(r'(\w+)', repository)
        if len(matches) == 3:
            return ''.join([c[0] for c in matches])
        elif len(matches) == 2:
            return matches[1]
        else:
            return repository
