from pathlib import Path
from pydantic import BaseModel


class InstanceParams(BaseModel):
    name: str
    role: str
    alias: str
    composite_name: str


class ProviderConfig(BaseModel):
    pass


class Instance(BaseModel):
    name: str
    params: InstanceParams
    path: str
    provider: str
    credential: str | Path
    connection_info: dict | None
    provider_config: ProviderConfig


class Inventory(BaseModel):
    name: str
    ansible_host: str
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str
    install: list[dict] | None


class VagrantConfig(ProviderConfig):
    cpu: int
    memory: int
    ip: str
    box: str
    box_version: str


class AWSConfig(ProviderConfig):
    pass
