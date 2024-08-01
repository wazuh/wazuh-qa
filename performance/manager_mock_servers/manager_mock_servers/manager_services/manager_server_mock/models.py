"""Testing."""
from pydantic import BaseModel


class AuthData(BaseModel):
    """Testing."""
    user: str
    password: str


class AgentData(BaseModel):
    """Testing."""
    uuid: str
    key: str
    name: str
