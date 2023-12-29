from pathlib import Path
from typing_extensions import Literal
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

from ..providers.generic import InstanceParams


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


class InputPayload(BaseModel):
    action: Literal['create', 'delete', 'status'] = 'create'
    provider: str | None
    size: str | None
    composite_name: str | None
    track_output: Path | None
    inventory_output: Path | None
    working_dir: Path | None
    custom_credentials: str | None


class CreationPayload(InputPayload):
    provider: str
    size: str
    composite_name: str
    track_output: Path
    inventory_output: Path
    working_dir: Path


class DeletionPayload(InputPayload):
    track_output: Path
