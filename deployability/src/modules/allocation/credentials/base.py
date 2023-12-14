from abc import ABC, abstractmethod
from pathlib import Path


class Credential(ABC):
    """Base class for Credentials"""
    class KeyCreationError(Exception):
        pass

    def __init__(self, base_dir: str | Path, name: str):
        """Initialize Credentials"""
        self.base_dir = Path(base_dir)
        self.name = str(name)

        self.private_key: Path = None
        self.public_key: Path = None

    @abstractmethod
    def generate_key(self, **kwargs) -> tuple[str, str] | None:
        """Generate credentials key pair"""
        pass

    @abstractmethod
    def delete(self, **kwargs):
        """Delete credentials key pair"""
        pass
