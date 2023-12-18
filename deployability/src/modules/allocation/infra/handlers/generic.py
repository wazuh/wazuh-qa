

from pathlib import Path
from pydantic import BaseModel


class ConnectionInfo(BaseModel):
    hostname: str
    user: str
    port: int
    private_key: str

class Handler:
    def __init__(self, working_dir: str | Path):
        """Initialize Handlers"""
        self.working_dir = Path(working_dir)
