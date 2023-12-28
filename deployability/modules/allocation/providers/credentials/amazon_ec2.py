import os
import boto3

from pathlib import Path

from .generic import Credentials


class AWSCredentials(Credentials):
    """
    A class for generating and deleting EC2 credentials.

    Attributes:
        path (Path): The path to store the credentials.
        name (str): The name of the credentials.
        key_pair (CredentialsKeyPair): The key pair.

    Raises:
        KeyCreationError: An error occurred while creating the key.

    """

    def __init__(self) -> None:
        """
        Initializes the AWSCredentials object.
        """
        self._resource = boto3.resource('ec2')
        self._client = boto3.client('ec2')
        super().__init__()

    def generate(self, base_dir: str | Path, name: str, overwrite: bool = False) -> Path:
        """
        Generates a new key pair and returns it.

        Args:
            overwrite (bool): Whether to overwrite the existing key pair. Defaults to False.

        Returns:
            AmazonEC2KeyPair: The paths of the key pair.

        """
        if self.key_path and self.key_id and not overwrite:
            return self.key_path
        if not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
        elif Path(base_dir).is_file():
            raise self.KeyCreationError(f"Invalid base directory: {base_dir}")

        private_key_path = Path(base_dir / name).with_suffix(".pem")

        if private_key_path.exists() and overwrite:
            private_key_path.unlink()
        elif private_key_path.exists():
            raise self.KeyCreationError(f"Key {name} already exists.")
        # Request the key pair from AWS.
        if response := self._client.describe_key_pairs(KeyNames=[name]):
            print(response)
            response = self._client.delete_key_pair(KeyName=name)
        (dir(self._resource))
        response = self._resource.create_key_pair(KeyName=name)
        key_pair_id = response.key_pair_id
        key_material = response.key_material
        with open(private_key_path, 'w') as key_file:
            key_file.write(key_material)
        os.chmod(private_key_path, 0o600)

        self.base_dir = base_dir
        self.name = name
        self.key_path = private_key_path
        self.key_id = key_pair_id
        return self.key_path
    
    def load(self, base_dir: str | Path, name: str) -> Path:
        """
        Loads an existing key pair and returns it.

        Args:
            base_dir (str | Path): The base directory to store the key pair.
            name (str): The name of the key pair.

        Returns:
            AmazonEC2KeyPair: The paths of the key pair.

        """
        base_dir = Path(base_dir)
        if base_dir.exists() or not base_dir.is_dir():
            raise self.KeyCreationError(f"Invalid path {base_dir}.")
        elif not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
        key_path = Path(base_dir, name).with_suffix(".pem")
        if key_path.exists():
            key_path.unlink()

        # Load the key pair from AWS.
        response = self._client.describe_key_pairs(KeyNames=[name])
        key_pair_id = response.key_pairs[0].key_pair_id
        if not key_pair_id:
            raise self.KeyCreationError(f"Invalid key name {name}.")
        with open(key_path, 'w') as key_file:
            key_file.write(response.key_pairs[0].key_material)
            os.chmod(key_file, 0o600)
        # Save instance attributes.
        self.base_dir = base_dir
        self.name = name
        self.key_path = key_path
        self.key_id = key_pair_id
        return self.key_path

    def delete(self) -> None:
        """Deletes the key pair."""
        if not self.key_pair:
            return
        self._resource.KeyPair(self.name).delete()
        Path(self.key_path).unlink()
        self.key_id = None
        self.key_path = None
