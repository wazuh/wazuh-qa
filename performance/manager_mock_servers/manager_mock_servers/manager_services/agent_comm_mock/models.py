from pydantic import BaseModel
from typing import Optional, List
import jwt
import datetime
import logging
from uuid import UUID


class AuthRequest(BaseModel):
    uuid: UUID
    key: Optional[str] = None

class StatelessEventData(BaseModel):
    id: int
    data: str

class StatefullEventData(BaseModel):
    id: int
    data: str

class StatelessEvent(BaseModel):
    events: List[StatelessEventData]

class StatefullData(BaseModel):
    events: List[StatefullEventData]
