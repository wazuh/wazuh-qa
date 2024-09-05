# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Tests for manager server mock."""
import os
import sqlite3
from typing import Generator

import pytest
from _pytest.tmpdir import TempPathFactory
from fastapi import status
from fastapi.testclient import TestClient

from manager_mock_services.manager_server_mock.manager_server_mock import (
    app,
    set_database_path,
)

client = TestClient(app)
DATABASE_NAME = 'agents.db'


@pytest.fixture(scope="session", autouse=True)
def init_db(tmp_path_factory: TempPathFactory) -> Generator:
    """Set up and tear down the test database.

    Creates a temporary SQLite database for the tests and sets the database
    path for the application. Cleans up by dropping the table and removing
    the database file after all tests in the session are finished.

    Args:
        tmp_path_factory: Factory for creating temporary directories.

    Yields:
        str: Path to the SQLite database file.
    """
    temporal_dir = tmp_path_factory.mktemp('agents_database')
    db_path = os.path.join(temporal_dir, DATABASE_NAME)
    set_database_path(str(temporal_dir))

    yield db_path

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE agents')
    conn.commit()
    conn.close()
    os.remove(db_path)


@pytest.fixture(scope="function")
def clean_database(init_db: str) -> None:
    """Clean up the database before each test.

    Deletes all entries from the 'agents' table in the database to ensure
    a clean state for each test.

    Args:
        init_db: Fixture that initializes the database.
    """
    conn = sqlite3.connect(init_db)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM agents;')
    conn.commit()
    conn.close()


@pytest.fixture
def auth_token() -> Generator:
    """Obtain an authentication token.

    Makes a request to the authentication endpoint using predefined
    credentials to obtain a token. Yields the token for use in tests.

    Yields:
        str: Authentication token.
    """
    username = 'username'
    password = 'password'
    response = client.post('/authentication',
                           json={'user': username, 'password': password}
                           )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()

    yield response.json().get('token')


def test_token(auth_token: str):
    """Test that the authentication token is valid.

    Verifies that the token obtained from the auth_token fixture is not None.

    Args:
        auth_token: The token obtained from the auth_token fixture.

    Assertions:
        Asserts auth token is not None
    """
    assert auth_token is not None


def test_agents(auth_token: str, clean_database: None):
    """Test successful agent registration.

    Registers a new agent using valid data and verifies that the response
    indicates successful registration.

    Args:
        auth_token: The token obtained from the auth_token fixture.
        clean_database: Fixture to ensure the database is clean before each test.

    Assertions:
        Asserts status_code is 200
        Asserts that response match with the expected agent correctly registered
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be",
                                 "key": "key", "name": "agent_name"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'message': 'Agent was correctly registered'}


def test_invalid_token(clean_database: None):
    """Test response with an invalid authentication token.

    Attempts to register an agent using an invalid token and verifies that
    the response indicates that the token is invalid.

    Args:
        clean_database: Fixture to ensure the database is clean before each test.

    Assertions:
        Asserts status_code is 403.
        Asserts that response match with the expected invalid jwt token.
    """
    headers = {"Authorization": "Bearer invalidtoken"}
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key", "name": "agent_name"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {'detail': 'Invalid JWT token'}


def test_missing_field(auth_token: str, clean_database: None):
    """Test agent registration with missing fields.

    Attempts to register an agent with missing required fields and verifies
    that the response indicates which field is missing.

    Args:
        auth_token: The token obtained from the auth_token fixture.
        clean_database: Fixture to ensure the database is clean before each test.

    Assertions:
        Asserts status_code is 422 when a request is perform with missing fields.
        Asserts that response match with expected missing field value.
    """
    def check_missing_field_in_response(response, field):
        return field in response.json()['detail'][0]['loc']

    headers = {"Authorization": f"Bearer {auth_token}"}

    # Missing 'uuid'
    response = client.post("/agents",
                           json={"key": "key", "name": "agent_name"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert check_missing_field_in_response(response, 'uuid')

    # Missing 'key'
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "name": "agent_name"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert check_missing_field_in_response(response, 'key')

    # Missing 'name'
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73bc", "key": "key"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert check_missing_field_in_response(response, 'name')


def test_invalid_data(auth_token: str, clean_database: None):
    """Test agent registration with invalid data.

    Attempts to register an agent with invalid data (e.g., invalid UUID or
    empty name) and verifies that the response indicates the nature of the
    data validation error.

    Args:
        auth_token: The token obtained from the auth_token fixture.
        clean_database: Fixture to ensure the database is clean before each test.

    Assertions:
        Asserts status_code is 422 when a request is perform with invalid data.
        Asserts that response match with the expected in case of invalid data is provided.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}

    response = client.post("/agents",
                           json={"uuid": "INVALID-UUID", "key": "key", "name": "agent_name"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert 'Input should be a valid UUID' in response.text

    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73bc", "key": "key", "name": ""},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert 'Missing parameters' in response.text


def test_duplicate_agent_uuid(auth_token: str, clean_database: None):
    """Test attempting to register an agent with a duplicate UUID.

    Registers an agent with a specific UUID and then attempts to register
    another agent with the same UUID. Verifies that the response indicates
    a conflict due to duplicate UUID.

    Args:
        auth_token: The token obtained from the auth_token fixture.
        clean_database: Fixture to ensure the database is clean before each test.

    Assertions:
        Asserts status_code is 409 when user tries to register an agent with duplicated uuid
        Asserts that response match with the expected in case of duplicated agent
    """
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Register first agent
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key1", "name": "agent_name1"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'message': 'Agent was correctly registered'}

    # Attempt to register duplicate agent
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key2",
                                 "name": "agent_name2"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json() == {'error': 'Agent with this credential already registered',
                               "uuid": "019121d5-712b-7bc4-8645-3124bc8d73be"}


def test_duplicate_agent_name(auth_token: str, clean_database: None):
    """Test attempting to register an agent with a duplicate name.

    Registers an agent with a specific name and then attempts to register
    another agent with the same name but a different UUID. Verifies that the
    response indicates a conflict due to duplicate agent name.

    Args:
        auth_token: The token obtained from the auth_token fixture.
        clean_database: Fixture to ensure the database is clean before each test.

    Assertions:
        Asserts status_code is 409 when user tries to register an agent with duplicated agent name
        Asserts that response match with the expected in case of duplicated agent
    """
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Register first agent
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key1", "name": "agent_name1"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'message': 'Agent was correctly registered'}

    # Attempt to register duplicate agent
    response = client.post("/agents",
                           json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key2", "name": "agent_name1"},
                           headers=headers
                           )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json() == {'error': 'Agent with this credential already registered', "name": "agent_name1"}
