from pydantic import BaseModel
from typing import Optional, List
import jwt
import datetime
import logging

# Configuration and constants
GLOBAL_AGENTS_PUBLIC_KEY = ''
default_iss = 'wazuh'
default_aud = 'Wazuh Agent comms API'
default_expiration_time = 900

# Initialize logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

# Global token storage (in-memory)
valid_tokens = {}

# Pydantic Models
class AuthRequest(BaseModel):
    uuid: str
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