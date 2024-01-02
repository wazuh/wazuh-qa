from pathlib import Path
from pydantic import BaseModel, IPvAnyAddress, field_validator
from typing_extensions import Literal


class ConnectionInfo(BaseModel):
    hostname: str
    user: str
    port: int
    private_key: str

    @field_validator('port', mode='before')
    @classmethod
    def sanitize_port(cls, v: str | int) -> int:
        return int(v)


class ProviderConfig(BaseModel):
    pass


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
    size: Literal['micro', 'small', 'medium', 'large', None]
    composite_name: str | None
    track_output: Path | None
    inventory_output: Path | None
    working_dir: Path | None
    custom_credentials: str | None


class CreationPayload(InputPayload):
    provider: str
    size: Literal['micro', 'small', 'medium', 'large']
    composite_name: str
    track_output: Path
    inventory_output: Path
    working_dir: Path
    custom_credentials: str | None = None

    @field_validator('custom_credentials')
    @classmethod
    def check_credentials(cls, v: str) -> str | None:
        if not v:
            return None
        path = Path(v)
        if not path.exists() or not path.is_file():
            raise ValueError(f"Invalid credentials path: {path}")
        return v

    @field_validator('working_dir', mode='before')
    @classmethod
    def check_working_dir(cls, v: str | Path) -> Path:
        path = Path(v)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        elif not path.is_dir():
            raise ValueError(f"Invalid working directory: {path}")
        return path


class DeletionPayload(InputPayload):
    track_output: Path
