# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from pathlib import Path
from pydantic import BaseModel, IPvAnyAddress, field_validator, model_validator
from typing_extensions import Literal

class ConnectionInfo(BaseModel):
    hostname: str
    user: str
    port: int
    private_key: str | None = None
    password: str | None = None

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
    ansible_ssh_private_key_file: str | None = None
    ansible_password: str | None = None
    ansible_connection: Literal['ssh', 'winrm'] | None = None
    ansible_winrm_server_cert_validation: Literal['ignore'] | None = None
    ansible_ssh_common_args: Literal['-o StrictHostKeyChecking=no'] | None = None


class TrackOutput(BaseModel):
    identifier: str
    name: str
    provider: str
    instance_dir: str
    key_path: str
    host_identifier: str = None
    host_instance_dir: str | Path = None
    ssh_port: int | None = None
    platform: str
    arch: str
    virtualizer: str | None = None


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
    instance_name: str | None = None
    rollback: bool

class CreationPayload(InputPayload):
    provider: str
    size: Literal['micro', 'small', 'medium', 'large'] | None = None
    composite_name: str | None = None
    track_output: Path | None = None
    inventory_output: Path | None = None
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


class TrackPayload(BaseModel):
    track_output: Path

class InstancePayload(BaseModel):
    identifier: str
    name: str | None = None
    instance_dir: str | Path
    key_path: Path | None = None
    host_identifier: str  | None = None
    host_instance_dir: str | Path | None = None
    remote_host_parameters: dict | None = None
    ssh_port: str | None = None
    platform: str
    arch: str | None = None
    user: str | None = None
    docker_image: str | None = None
    virtualizer: str | None = None

    @field_validator('ssh_port', mode='before')
    def validate_port(cls, value) -> str | None:
        if not value:
            return

        return str(value)
