import os
import subprocess

from pathlib import Path

from .base import Credential


class VagrantCredential(Credential):

    def __init__(self, base_dir: str | Path, name: str) -> None:
        super().__init__(base_dir, name)

    def generate_key(self, overwrite: bool = False) -> tuple[str, str] | None:
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
        if self.private_key:
            self.private_key.unlink(missing_ok=True)
            self.private_key = None
        if self.public_key:
            self.public_key.unlink(missing_ok=True)
            self.public_key = None
