from pathlib import Path
from pydantic import field_validator

from modules.allocation.generic.models import ProviderConfig


class VagrantConfig(ProviderConfig):
    ip: str
    cpu: int
    memory: int
    box: str
    box_version: str
    private_key: str
    public_key: str
    name: str

    @field_validator('public_key', mode='before')
    @classmethod
    def check_public_key(cls, v: str) -> str:
        path = Path(v)
        if not path.exists() or not path.is_file():
            raise ValueError(f"Invalid public key path: {path}")
        return v
