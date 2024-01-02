import os
import boto3

from pathlib import Path

from modules.allocation.generic import Credentials


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
        super().__init__()
        self._resource = boto3.resource('ec2')
        self._client = boto3.client('ec2')

    def generate(self, base_dir: str | Path, name: str) -> Path:
        """
        Generates a new key pair and returns it.

        Args:
            base_dir (str | Path): The base directory to store the key pair.
            name (str): The name of the key pair.

        Returns:
            AmazonEC2KeyPair: The paths of the key pair.

        """
        if not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
        elif Path(base_dir).is_file():
            raise self.KeyCreationError(f"Invalid base directory: {base_dir}")
        private_key_path = None
        # Request the key pair from AWS.
        try:
            response = self._resource.create_key_pair(KeyName=name)
        except:
            # No necesito agarrar la key desde aca, puede no guardarse y ya
            response = self._resource.key_pairs.filter(KeyNames=[name])
            response = [key for key in response][0]
        if hasattr(response, 'key_material'):
            private_key_path = base_dir / name
            key_material = response.key_material
            with open(private_key_path, 'w') as key_file:
                key_file.write(key_material)
            os.chmod(private_key_path, 0o600)
        # Save instance attributes.
        self.name = name
        self.key_path = private_key_path
        self.key_id = response.key_pair_id
        return self.key_path

    def load(self, name: str) -> str:
        """
        Loads an existing key pair and returns it.

        Args:
            name (str): The name of the key pair.

        Returns:
            str: The id of the key pair.

        """
        # Load the key pair from AWS.
        response = self._resource.describe_key_pairs(KeyNames=[name])
        key_pair_id = response.key_pairs[0].key_pair_id
        if not key_pair_id:
            raise self.KeyCreationError(f"Invalid key name {name}.")
        # Save instance attributes.
        self.name = name
        self.key_id = key_pair_id
        return self.key_id

    def delete(self) -> None:
        """Deletes the key pair."""
        if not self.key_pair:
            return
        self._resource.KeyPair(self.name).delete()
        Path(self.key_path).unlink()
        self.key_id = None
        self.key_path = None
