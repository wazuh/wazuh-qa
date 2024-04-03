# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess

from pathlib import Path

from modules.allocation.generic import Credentials
from modules.allocation.generic.utils import logger


class VagrantCredentials(Credentials):
    """
    A class for generating and deleting Vagrant credentials.

    Attributes:
        path (Path): The path to store the credentials.
        name (str): The name of the credentials.
        public_key (Path): The key path.

    Raises:
        CredentialsError: An error occurred while creating the key.

    """

    def generate(self, base_dir: str | Path, name: str) -> Path:
        """
        Generates a new SSH key pair and returns the path to the private key.

        Args:
            base_dir (str | Path): The directory where the key pair will be stored.
            name (str): The filename of the key pair.
            overwrite (bool, optional): If True, an existing key pair with the same name will be overwritten. Defaults to False.

        Returns:
            Path: The path to the private key of the generated key pair.

        Raises:
            CredentialsError: This exception is raised if there's an error during the key creation process.
        """
        if self.key_path and self.key_id:
            logger.warning(f"Key pair already exists: {self.key_path}")
            return self.key_path

        base_dir = Path(base_dir)
        if not base_dir.exists():
            logger.debug(f"Creating base directory: {base_dir}")
            base_dir.mkdir(parents=True, exist_ok=True)
        elif Path(base_dir).is_file():
            raise self.CredentialsError(f"Invalid base directory: {base_dir}")

        private_key_path = Path(base_dir / name)
        public_key_path = private_key_path.with_suffix(".pub")
        # Delete the existing key pair if it exists.
        if private_key_path.exists():
            logger.warning(f"Key pair already exists: {private_key_path}")
            return self.load(base_dir, name)
        elif private_key_path.exists():
            private_key_path.unlink()
        if public_key_path.exists():
            public_key_path.unlink()
        # Generate the key pair.
        command = ["ssh-keygen",
                    "-f", str(private_key_path),
                    "-m", "PEM",
                    "-t", "rsa",
                    "-N", "",
                    "-q"]
        output = subprocess.run(command, check=True,
                                capture_output=True, text=True)
        os.chmod(private_key_path, 0o600)
        if output.returncode != 0:
            raise self.CredentialsError(f"Error creating key pair: {output.stderr}")

        # Save instance attributes.
        self.name = name
        self.key_id = name
        self.key_path = private_key_path
        return self.key_path

    def load(self, path: str | Path) -> None:
        """
        Loads an existing key pair from the specified directory.

        Args:
            path (str | Path): The path to the key pair.

        Raises:
            CredentialsError: This exception is raised if the key pair doesn't exist or the specified directory is invalid.
        """
        if path.endswith('.pub'):
            key_path = Path(os.path.splitext(path)[0])
        else:
            key_path = Path(path)
        if not key_path.exists() or not key_path.is_file():
            raise self.CredentialsError(f"Invalid key path {key_path}.")
        self.key_path = key_path
        self.name = key_path.name
        self.key_id = key_path.name

    def delete(self) -> None:
        """
        Deletes the key pair from the file system.
        """
        if not self.key_path.exists():
            logger.warning(f"Key pair doesn't exist: {self.key_path}.\
                            Skipping deletion.")
            return
        Path(self.key_path).unlink()
        Path(self.key_path.with_suffix(".pub")).unlink()
        self.key_id = None
        self.key_path = None

    def ssh_key_interpreter(self, ssh_key_path: str | Path) -> str:
        """
        Gets the path of the public SSH Key from the provisioned public or private key

        Args:
            public_key_path (str): The public or private key path or aws key id.

        Returns:
            str: The path of the public key.

        Raises:
            CredentialsError: An error occurred during key pair loading.
        """
        if not ssh_key_path.endswith('.pub'):
            ssh_key_path = ssh_key_path + ".pub"
        return ssh_key_path
