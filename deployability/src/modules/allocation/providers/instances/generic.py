from abc import ABC, abstractmethod
from pathlib import Path
from pydantic import BaseModel


class ConnectionInfo(BaseModel):
    hostname: str
    user: str
    port: int
    private_key: str | Path


class Instance(ABC):
    def __init__(self, base_dir: Path, name: str, identifier: str, key_pair: Path = None) -> None:
        """Initialize Instance object."""
        instance_path = Path(base_dir, identifier)
        if not instance_path.exists() or not instance_path.is_dir():
            raise ValueError(f"Invalid instance base_path or identifier: {instance_path}")
        if key_pair and not Path(key_pair).exists():
            raise ValueError(f"Invalid key pair path: {key_pair}")

        self.path: Path = instance_path
        self.name: str = str(name)
        self.identifier: str = str(identifier)
        self.key_pair: Path = Path(key_pair) if key_pair else None


    @abstractmethod
    def start(self) -> None:
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
