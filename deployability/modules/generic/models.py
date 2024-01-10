
from pydantic import BaseModel, IPvAnyAddress


class AnsibleInventory(BaseModel):
    ansible_host: str | IPvAnyAddress
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str
