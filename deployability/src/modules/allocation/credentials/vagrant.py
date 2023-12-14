import os
import subprocess

from pathlib import Path

from .base import Credential


class VagrantCredential(Credential):
    """
    A class for generating and deleting Vagrant credentials.

    Attributes:
        base_dir (Path): The base directory for the credentials.
        name (str): The name of the credentials.
        private_key (Path): The path to the private key.
        public_key (Path): The path to the public key.

    Raises:
        KeyCreationError: An error occurred while creating the key.

    """

    def __init__(self, base_dir: str | Path, name: str) -> None:
        """
        Initializes the VagrantCredential object.

        Args:
            base_dir (Path): The base directory for the credentials.
            name (str): The name of the credentials.
        """
        super().__init__(base_dir, name)

    def generate_key(self, overwrite: bool = False) -> tuple[str, str] | None:
        """
        Generates a new key pair and returns it.

        Args:
            overwrite (bool): Whether to overwrite the existing key pair. Defaults to False.

        Returns:
            tuple(str, str): The paths to the private and public keys.

        Raises:
            KeyCreationError: An error occurred while creating the key.

        """
        if self.private_key and self.public_key and not overwrite:
            return str(self.private_key), str(self.public_key)
        if not self.base_dir.exists():
            self.base_dir.mkdir(parents=True, exist_ok=True)

        path = self.base_dir / self.name
        command = ["ssh-keygen",
                   "-f", str(path),
                   "-m", "PEM",
                   "-t", "rsa",
                   "-N", "",
                   "-q"]
        output = subprocess.run(command, check=True, capture_output=True, text=True)
        os.chmod(path, 0o600)
        if output.returncode != 0:
            raise self.KeyCreationError(f"Error creating key pair: {output.stderr}")

        self.private_key = path
        self.public_key = path.with_suffix(".pub")

        return str(self.private_key), str(self.public_key)

    def delete(self) -> None:
        """Deletes the key pair."""
        if self.private_key:
            self.private_key.unlink(missing_ok=True)
            self.private_key = None
        if self.public_key:
            self.public_key.unlink(missing_ok=True)
            self.public_key = None
