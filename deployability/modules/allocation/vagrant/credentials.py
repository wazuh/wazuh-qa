import os
import subprocess

from pathlib import Path

from modules.allocation.generic import Credentials


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
            return self.key_path
        base_dir = Path(base_dir)
        if not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
        elif Path(base_dir).is_file():
            raise self.CredentialsError(f"Invalid base directory: {base_dir}")

        private_key_path = Path(base_dir / name)
        public_key_path = private_key_path.with_suffix(".pub")
        # Delete the existing key pair if it exists.
        if private_key_path.exists():
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
            raise self.CredentialsError(
                f"Error creating key pair: {output.stderr}")
        # Save instance attributes.
        self.name = name
        self.key_id = name
        self.key_path = private_key_path
        return self.key_path

    def load(self, base_dir: str | Path, name: str) -> None:
        """
        Loads an existing key pair from the specified directory.

        Args:
            base_dir (str | Path): The directory where the key pair is stored.
            name (str): The filename of the key pair.

        Raises:
            CredentialsError: This exception is raised if the key pair doesn't exist or the specified directory is invalid.
        """
        base_dir = Path(base_dir)
        if not base_dir.exists() or not base_dir.is_dir():
            raise self.CredentialsError(f"Invalid path {base_dir}.")
        key_path = Path(base_dir, name)
        pub_key_path = key_path.with_suffix(".pub")
        if not key_path.exists() or not key_path.is_file():
            raise self.CredentialsError(f"Invalid key name {name}.")
        if not pub_key_path.exists() or not pub_key_path.is_file():
            raise self.CredentialsError(f"Non-existen public key for {name}.")
        # Save instance attributes.
        self.key_path = key_path
        self.name = name
        self.key_id = name

    def delete(self) -> None:
        """
        Deletes the key pair from the file system.
        """
        if not self.key_path.exists():
            return
        Path(self.key_path).unlink()
        Path(self.key_path.with_suffix(".pub")).unlink()
        self.key_id = None
        self.key_path = None
