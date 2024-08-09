"""This module defines Pydantic models used for representing various types of events and authentication requests.

Classes:
- AuthRequest: Represents an authentication request with a unique identifier and an optional key.
- StatelessEventData: Represents the data for a stateless event, including a unique identifier and associated data.
- StatefullEventData: Represents the data for a stateful event, including a unique identifier and associated data.
- StatelessEvent: Represents a collection of stateless events.
- StatefullData: Represents a collection of stateful events.
"""

from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel


class AuthRequest(BaseModel):
    """Represents an authentication request.

    Attributes:
        uuid (UUID): A unique identifier for the authentication request.
        key (Optional[str]): An optional authentication key. Can be None if not required.
    """
    uuid: UUID
    key: Optional[str] = None


class StatelessEventData(BaseModel):
    """Represents the data for a stateless event.

    Attributes:
        id (int): The unique identifier for the event.
        data (str): The data associated with the event.
    """
    id: int
    data: str


class StatefullEventData(BaseModel):
    """Represents the data for a stateful event.

    Attributes:
        id (int): The unique identifier for the event.
        data (str): The data associated with the event.
    """
    id: int
    data: str


class StatelessEvents(BaseModel):
    """Represents a collection of stateless events.

    Attributes:
        events (List[StatelessEventData]): A list of stateless event data.
    """
    events: List[StatelessEventData]


class StatefullEvents(BaseModel):
    """Represents a collection of stateful events.

    Attributes:
        events (List[StatefullEventData]): A list of stateful event data.
    """
    events: List[StatefullEventData]
