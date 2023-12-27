
from pydantic import BaseModel

from .providers import VagrantProvider, AmazonEC2, Provider

PROVIDERS = {'vagrant': VagrantProvider, 'infra': 'AmazonEC2'}


class AllocationPayload(BaseModel):
    name: str
    provider: str
    alias: str
    composite_name: str
    size: str


class Allocation:
    def create(self,  base_dir: str, payload: AllocationPayload, credentials: dict = None):
        if not isinstance(payload, AllocationPayload):
            payload = AllocationPayload(**payload)
        payload = payload
        provider: Provider = PROVIDERS[payload.provider]()
        instance = provider.create_instance(payload, base_dir, credentials)
        return instance.inventory
    
    # def load(self, )