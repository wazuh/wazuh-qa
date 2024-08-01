from pydantic import BaseModel
from typing import Optional, List
import jwt
import datetime
import logging
from uuid6 import uuid7


class AuthRequest(BaseModel):
    uuid: uuid7
    key: Optional[str] = None

class StatelessEventData(BaseModel):
    id: int
    data: str

class StatelessEvent(BaseModel):
    events: List[StatelessEventData]

class StatefullData(BaseModel):
    # Add fields as required for stateful data
    pass


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