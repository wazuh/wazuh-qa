# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv
""""Tests for agent comm mock service."""
import os
import sqlite3
import time
from typing import Generator

import pytest
from _pytest.tmpdir import TempPathFactory
from fastapi import status
from fastapi.testclient import TestClient

from manager_mock_servers.manager_services.agent_comm_mock.agent_comm_mock import (
    app,
    router_version,
    set_database_path,
    set_report_file,
)
from manager_mock_servers.utils.agent_database_handler import create_agents_database, insert_new_agent

TESTING_VERSION = "/v33"
app.include_router(router_version, prefix=TESTING_VERSION)

client = TestClient(app)
DATABASE_NAME = 'agents.db'

UUID = '019126aa-16e1-7009-af24-2d64875104bc'
KEY = 'key'
NAME = 'agent1'


@pytest.fixture(scope="module", autouse=True)
def configure_report_file(tmp_path_factory: TempPathFactory) -> Generator:
    """Fixture to configure the report file.

    Creates a temporary directory and sets the path for the report file
    used for metrics. Yields the path to the report file for use in tests.

    Args:
        tmp_path_factory: Factory for creating temporary directories.

    Yields:
        str: Path to the metrics report file.
    """
    temporal_dir = tmp_path_factory.mktemp('metrics')
    report_file = os.path.join(temporal_dir, 'metrics.csv')
    set_report_file(report_file)

    yield report_file


@pytest.fixture(scope="module")
def init_db(tmp_path_factory: TempPathFactory) -> Generator:
    """Fixture to initialize and clean up the test database.

    Sets up a temporary SQLite database for testing, and provides the path
    to the database file. Cleans up by deleting the database file after
    tests are done.

    Args:
        tmp_path_factory: Factory for creating temporary directories.

    Yields:
        str: Path to the SQLite database file.
    """
    temporal_dir = tmp_path_factory.mktemp('agents_database')
    db_path = os.path.join(temporal_dir, DATABASE_NAME)
    create_agents_database(str(temporal_dir))
    set_database_path(db_path)

    yield db_path

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE agents')
    conn.commit()
    conn.close()
    os.remove(db_path)


@pytest.fixture(scope="module")
def mock_agent_register(init_db: str) -> None:
    """Fixture to register a mock agent.

    Inserts a test agent into the database for testing purposes. Requires
    the database to be initialized before inserting the agent.

    Args:
        init_db: Fixture that initializes the database.
    """
    db_path = init_db
    insert_new_agent(db_path, UUID, KEY, NAME)


@pytest.fixture
def auth_token(init_db: str, mock_agent_register: None) -> Generator:
    """Fixture to obtain an authentication token.

    Makes a request to the authentication endpoint to retrieve a token
    using the mock agent's credentials. Yields the token for use in tests.

    Args:
        init_db: Fixture that initializes the database.
        mock_agent_register: Fixture that registers a mock agent.

    Yields:
        str: Authentication token.
    """
    response = client.post(f"{TESTING_VERSION}/authentication",
                           json={"uuid": UUID, "key": KEY}
                           )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()

    yield response.json().get('token')


def test_token(auth_token: str):
    """Test that the authentication token is valid.

    Ensures that the authentication token retrieved is not None.

    Args:
        auth_token: The token obtained from the auth_token fixture.

    Assertions:
        Asserts agent comm tokens is not None.
    """
    assert auth_token is not None


def test_stateless_event(auth_token: str):
    """Test posting a stateless event.

    Posts a stateless event to the events endpoint and verifies that the
    response indicates that the event was received successfully.

    Args:
        auth_token: The token obtained from the auth_token fixture.

    Assertions:
        Asserts response code is 200.
        Asserts response message match with the expected.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    events = {"events": [
                        {"id": 1, "data": "test_data"}
                    ]}
    response = client.post(f'{TESTING_VERSION}/events/stateless', json=events,
                           headers=headers)
    assert response.status_code == 200
    assert response.json() == {'message': 'Event received'}


def test_stateful_event(auth_token: str):
    """Test posting a stateful event.

    Posts a stateful event to the events endpoint and verifies that the
    response indicates that the event is being processed and will be persisted.

    Args:
        auth_token: The token obtained from the auth_token fixture.

    Assertions:
        Asserts response code is 200.
        Asserts response message match with the expected.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    events = {"events": [
                        {"id": 1, "data": "test_data"}
                    ]}
    response = client.post(f'{TESTING_VERSION}/events/stateful', json=events,
                           headers=headers)

    assert response.status_code == 200
    assert response.json() == {'message': 'Event is being processed and will be persisted'}


def test_metrics_file(configure_report_file: str):
    """Test that the metrics report file is created.

    Ensures that the metrics report file exists after the tests have run.
    Introduces a delay to allow time for file creation.

    Args:
        configure_report_file: Fixture that sets up the metrics report file.

    Assertions:
        Asserts metrics file is created.
    """
    with TestClient(app):
        time.sleep(10)
        assert os.path.exists(configure_report_file)

