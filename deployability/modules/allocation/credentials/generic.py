from abc import ABC, abstractmethod
from pathlib import Path


class Credentials(ABC):
    """Base class for Credentialss"""
    class KeyCreationError(Exception):
        pass

    def __init__(self) -> None:
        """Initialize Credentialss"""
        self.name: str = None
        self.base_dir: Path = None
        self.key_path: Path = None
        self.key_id: str = None  # De aca saco el .pub en vagrant y en amazon saco el id

    @abstractmethod
    def generate(self, **kwargs) -> Path:
        """Generate credentials key pair"""
        pass

    @abstractmethod
    def load(self, **kwargs) -> Path:
        """Load credentials key pair"""
        pass

    @abstractmethod
    def delete(self, **kwargs) -> None:
        """Delete credentials key pair"""
        pass
