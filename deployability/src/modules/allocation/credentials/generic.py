from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel


class CredentialsKeyPair(BaseModel):
    private_key: str
    public_key: str


class Credentials(ABC):
    """Base class for Credentialss"""
    class KeyCreationError(Exception):
        pass

    def __init__(self, path: str | Path, name: str):
        """Initialize Credentialss"""
        self.path = Path(path)
        self.name = str(name)
        self.key_pair: CredentialsKeyPair = None

    @abstractmethod
    def generate_key_pair(self, **kwargs) -> tuple[str, str] | None:
        """Generate credentials key pair"""
        pass

    @abstractmethod
    def delete_key_pair(self, **kwargs):
        """Delete credentials key pair"""
        pass
