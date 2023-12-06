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
    status: str
    params: dict
    path: str
    id: str
    credential: str
    connection_info: dict
    provider: str
    provider_config: VagrantConfig | AWSConfig
