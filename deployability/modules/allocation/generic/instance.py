from abc import ABC, abstractmethod
from pathlib import Path

from .credentials import Credentials
from .models import ConnectionInfo



class Instance(ABC):
    def __init__(self, path: str | Path, identifier: str, credentials: Credentials = None) -> None:
        """Initialize Instance object."""
        path = Path(path)
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Invalid instance path: {path}")
        if credentials and not issubclass(type(credentials), Credentials):
            raise ValueError(f"Invalid credentials.")

        self.path: Path = path
        self.identifier: str = str(identifier)
        self.credentials: Credentials = credentials

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def reload(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def delete(self) -> None:
        pass

    @abstractmethod
    def status(self) -> str:
        pass

    @abstractmethod
    def ssh_connection_info(self) -> ConnectionInfo:
        pass
