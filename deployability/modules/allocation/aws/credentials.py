import os
import boto3

from botocore.exceptions import ClientError
from pathlib import Path

from modules.allocation.generic import Credentials
from modules.allocation.generic.utils import logger


class AWSCredentials(Credentials):
    """
    A class for generating and deleting EC2 credentials.

    Attributes:
        path (Path): The path to store the credentials.
        name (str): The name of the credentials.
        key_pair (CredentialsKeyPair): The key pair.

    Raises:
        CredentialsError: An error occurred while creating the key.
    """

    def __init__(self) -> None:
        """
        Initializes the AWSCredentials object.
        """
        super().__init__()
        self._resource = boto3.resource('ec2')

    def generate(self, base_dir: str | Path, name: str, overwrite: bool = False) -> Path:
        """
        Generates a new key pair and returns it.

        Args:
            base_dir (str | Path): The base directory to store the key pair.
            name (str): The name of the key pair.
            overwrite (bool): Whether to overwrite if the key pair already exists.

        Returns:
            Path: The path of the private key.

        Raises:
            CredentialsError: An error occurred during key pair creation.
        """
        base_dir = Path(base_dir)

        # Validate base directory
        if not base_dir.exists():
            logger.debug(f"Creating base directory: {base_dir}")
            base_dir.mkdir(parents=True, exist_ok=True)
        elif base_dir.is_file():
            raise self.CredentialsError(f"Invalid base directory: {base_dir}")

        try:
            # Check if the key pair already exists
            key_pair = self._resource.KeyPair(name)
            if key_pair.key_pair_id:
                if not overwrite:
                    raise self.CredentialsError(f"Key pair {name} already exists.")
                else:
                    logger.warning(f"Key pair {name} already exists. Overwriting.")
                    key_pair.delete()
        except ClientError:
            pass

        try:
            private_key_path = base_dir / name
            # Create the new key pair
            key_pair = self._resource.create_key_pair(KeyName=name)
            key_material = key_pair.key_material

            # Save the private key
            with open(private_key_path, 'w') as key_file:
                key_file.write(key_material)
            os.chmod(private_key_path, 0o600)

            # Save instance attributes
            self.name = name
            self.key_path = private_key_path
            self.key_id = key_pair.key_pair_id

            return self.key_path
        except Exception as e:
            raise self.CredentialsError(f"Failed to create key pair: {str(e)}")

    def load(self, name: str) -> str:
        """
        Loads an existing key pair and returns its ID.

        Args:
            name (str): The name of the key pair.

        Returns:
            str: The ID of the key pair.

        Raises:
            CredentialsError: An error occurred during key pair loading.
        """
        try:
            # Load the key pair from AWS
            key_pair = self._resource.KeyPair(name)

            if not key_pair.key_pair_id:
                raise self.CredentialsError(f"Invalid key name {name}")

            # Save instance attributes
            self.name = name
            self.key_id = key_pair.key_pair_id

            return self.key_id
        except Exception as e:
            raise self.CredentialsError(f"Failed to load key pair: {str(e)}")

    def delete(self) -> None:
        """Deletes the key pair."""
        if not self.name:
            logger.warning(f"Key pair doesn't exist. Skipping deletion.")
            return

        try:
            # Delete the key pair from AWS
            self._resource.KeyPair(self.name).delete()
        except Exception as e:
            raise self.CredentialsError(f"Failed to delete key pair: {str(e)}")

        # Remove the local private key file
        if self.key_path:
            logger.debug(f"Deleting private key: {self.key_path}")
            Path(self.key_path).unlink()

        # Clear instance attributes
        self.name = None
        self.key_id = None
        self.key_path = None