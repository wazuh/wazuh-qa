from pydantic import BaseModel
from typing import Optional
import jwt

class AuthData(BaseModel):
    user: str
    password: str

class AgentData(BaseModel):
    uuid: str
    key: str
    name: str


class TokenManager:
    @staticmethod
    def generate_token(iss: str, aud: str, iat: int, exp: int, uuid: str, credential: str) -> str:
        payload = {
            'iss': iss,
            'aud': aud,
            'iat': iat,
            'exp': exp,
            'uuid': uuid
        }
        token = jwt.encode(payload, credential, algorithm='HS256')
        return token