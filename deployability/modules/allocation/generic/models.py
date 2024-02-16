from pathlib import Path
from pydantic import BaseModel, IPvAnyAddress, field_validator, model_validator
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
    provider: str | None = None
    size: Literal['micro', 'small', 'medium', 'large', None] = None
    composite_name: str | None = None
    working_dir: Path | None = Path('/tmp/wazuh-qa')
    track_output: Path | None = working_dir / 'track.yml'
    inventory_output: Path | None = working_dir / 'inventory.yml'
    ssh_key: str | None = None
    custom_provider_config: Path | None = None
    label_issue: str | None = None
    label_team: str | None = None
    label_termination_date: str | None = None

class CreationPayload(InputPayload):
    provider: str
    size: Literal['micro', 'small', 'medium', 'large'] | None = None
    composite_name: str | None = None
    track_output: Path
    inventory_output: Path
    working_dir: Path
    ssh_key: str | None = None
    custom_provider_config: Path | None = None
    label_issue: str | None = None
    label_team: str | None = None
    label_termination_date: str | None = None

    @model_validator(mode='before')
    def validate_dependency(cls, values) -> dict:
        """Validate required fields."""
        required_if_not_config = ['composite_name', 'size']
        if values.get('custom_provider_config'):
            return values
        for attr in required_if_not_config:
            if not values.get(attr):
                raise ValueError(f"{attr} is required if custom_provider_config is not provided.")
        return values

    @field_validator('custom_provider_config')
    @classmethod
    def check_config(cls, v: Path | None) -> Path | None:
        if not v:
            return None
        if not v.exists():
            raise ValueError(f"Custom provider config file does not exist: {v}")
        elif not v.is_file():
            raise ValueError(f"Custom provider config file is not a file: {v}")
        elif not v.suffix in ['.yml', '.yaml']:
            raise ValueError(f"Custom provider config file must be yaml: {v}")
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
