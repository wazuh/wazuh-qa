# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Module for defining data models used in authentication and agent management for manager API mocks.

This module contains models that represent the structure of
authentication credentials and agent information. These models are used
to ensure that the data conforms to the expected format and constraints
when interacting with authentication systems or managing agents.

Classes:
    AuthData: Represents authentication credentials including user and password.
    AgentData: Represents information about an agent, including uuid, key, and name.
"""
from uuid import UUID

from pydantic import BaseModel


class AuthData(BaseModel):
    """A data model representing authentication credentials.

    Attributes:
        user (str): The username or identifier used for authentication.
        password (str): The password associated with the user.
    """
    user: str
    password: str


class AgentData(BaseModel):
    """A data model representing information about an agent.

    Attributes:
        uuid (str): A unique identifier for the agent.
        key (str): A secret key associated with the agent.
        name (str): The name of the agent.
    """
    uuid: UUID
    key: str
    name: str
