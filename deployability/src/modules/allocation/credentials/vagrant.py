import os
import subprocess

from pathlib import Path

from .generic import Credentials, CredentialsKeyPair


class VagrantCredentials(Credentials):
    """
    A class for generating and deleting Vagrant credentials.

    Attributes:
        path (Path): The path to store the credentials.
        name (str): The name of the credentials.
        key_pair (CredentialsKeyPair): The key pair.

    Raises:
        KeyCreationError: An error occurred while creating the key.

    """

    def __init__(self, path: str | Path, name: str) -> None:
        """
        Initializes the VagrantCredentials object.

        Args:
            path (Path): The path to store the credentials.
            name (str): The name of the credentials.
        """
        super().__init__(path, name)

    def generate_key_pair(self, overwrite: bool = False) -> CredentialsKeyPair:
        """
        Generates a new key pair and returns it.

        Args:
            overwrite (bool): Whether to overwrite the existing key pair. Defaults to False.

        Returns:
            CredentialsKeyPair: The paths of the key pair.

        Raises:
            KeyCreationError: An error occurred while creating the key.

        """
        if self.key_pair and not overwrite:
            return self.key_pair

        private_key_path = Path(self.path / self.name)
        public_key_path = private_key_path.with_suffix(".pub")
        # Create the base directory if it doesn't exist.
        if not self.path.exists():
            self.path.mkdir(parents=True, exist_ok=True)
        # Delete the existing key pair if it exists.
        if private_key_path.exists():
            private_key_path.unlink()
        if public_key_path.exists():
            public_key_path.unlink()

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
            raise self.KeyCreationError(
                f"Error creating key pair: {output.stderr}")
        self.key_pair = CredentialsKeyPair(public_key=str(public_key_path),
                                           private_key=str(private_key_path))
        return self.key_pair

    def delete_key_pair(self) -> None:
        """Deletes the key pair."""
        if not self.key_pair:
            return
        Path(self.key_pair.private_key).unlink()
        Path(self.key_pair.public_key).unlink()
        self.key_pair = None
