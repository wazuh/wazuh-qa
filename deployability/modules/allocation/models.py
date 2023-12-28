from pathlib import Path
from typing_extensions import Literal
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

from .providers.generic import InstanceParams


class InventoryOutput(BaseModel):
    ansible_host: str | IPvAnyAddress
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str


class TrackOutput(BaseModel):
    identifier: str
    provider: str
    instance_dir: str
    key_path: str


class InputPayload(InstanceParams):
    action: Literal['create', 'delete', 'status'] = Field(default='create', description='Action to perform.')
    track_output: Path = Field(default=None, description='Path to the track output file.')
    inventory_output: Path = Field(default=None, description='Path to the inventory output file.')

    @field_validator('track_output', 'inventory_output', mode='before')
    @classmethod
    def check_path_is_valid(cls, v: str | Path) -> Path:
        path = Path(v)
        if not path.parent.exists() or not path.parent.is_dir():
            raise ValueError(f"Invalid path: {path}")
        return path
