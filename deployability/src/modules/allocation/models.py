from pathlib import Path
from pydantic import BaseModel



class Inventory(BaseModel):
    ansible_host: str
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str
