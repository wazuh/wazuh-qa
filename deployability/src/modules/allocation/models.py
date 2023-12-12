from pydantic import BaseModel


class VagrantConfig(BaseModel):
    cpu: int
    memory: int
    ip: str
    box: str
    box_version: str


class AWSConfig(BaseModel):
    pass


class InstanceParams(BaseModel):
    name: str
    role: str
    alias: str
    composite_name: str


class Instance(BaseModel):
    name: str
    params: InstanceParams
    path: str
    provider: str
    credential: str | None
    connection_info: dict | None
    provider_config: VagrantConfig | AWSConfig


class Inventory(BaseModel):
    name: str
    ansible_host: str
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str
    install: list[dict] | None
