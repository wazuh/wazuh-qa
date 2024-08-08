# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Tests for agent database handler."""
import os
import sqlite3
from typing import Generator

import pytest
from _pytest.tmpdir import TempPathFactory

from manager_mock_servers.utils.agent_database_handler import (
    check_if_agent_exists,
    check_if_uuid_exists,
    create_agents_database,
    insert_new_agent,
)


@pytest.fixture
def create_agent_database(tmp_path_factory: TempPathFactory) -> Generator:
    """Fixture to create a new SQLite database for testing with the 'agents' table.

    Args:
        tmp_path_factory (TempPathFactory): Factory for creating temporary directories.

    Yields:
        str: Path of the database path
    """
    agent_database_path = tmp_path_factory.mktemp('db')
    db_path = create_agents_database(str(agent_database_path))

    yield db_path


def test_create_agents_database(create_agent_database: str):
    """Verify that the agents database is created with the correct table structure.

    Asserts that the database file exists and that the 'agents' table contains the
    expected columns: 'id', 'uuid', 'credential', and 'name'.

    Args:
        create_agent_database (str): Path with the database for testing.

    Assertions:
        Asserts that created database exists and match the expected.
    """
    assert os.path.exists(create_agent_database)

    # Check that the table was created
    with sqlite3.connect(create_agent_database) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(agents);")
        columns = [column[1] for column in cursor.fetchall()]
        expected_columns = ['id', 'uuid', 'credential', 'name']
        assert set(columns) == set(expected_columns)


def test_check_if_agent_exists(create_agent_database: str):
    """Verify the functionality of the 'check_if_agent_exists' function.

    Inserts a new agent into the database and checks that the agent can be
    correctly retrieved by its name. Also verifies that a non-existent agent
    returns None.

    Args:
        create_agent_database (str): Path with the database for testing.

    Assertions:
        Asserts that inserted agent is correctly detected by agent name
    """
    insert_new_agent(create_agent_database, 'uuid-1234', 'key-1234', 'Agent1')

    result = check_if_agent_exists(create_agent_database, 'Agent1')
    assert result is not None
    assert result[1] == 'uuid-1234'
    assert result[2] == 'key-1234'
    assert result[3] == 'Agent1'

    # Check for a non-existent agent
    result = check_if_agent_exists(create_agent_database, 'NonExistentAgent')
    assert result is None


def test_check_if_uuid_exists(create_agent_database: str):
    """Verify the functionality of the 'check_if_uuid_exists' function.

    Inserts a new agent into the database and checks that the UUID can be
    correctly retrieved. Also verifies that a non-existent UUID returns None.

    Args:
        create_agent_database (str): Path with the database for testing.

    Assertions:
        Asserts that inserted agent is correctly detected by uuid
    """
    insert_new_agent(create_agent_database, 'uuid-5678', 'key-5678', 'Agent2')

    result = check_if_uuid_exists(create_agent_database, 'uuid-5678')
    assert result is not None
    assert result[1] == 'uuid-5678'
    assert result[2] == 'key-5678'
    assert result[3] == 'Agent2'

    # Check for a non-existent UUID
    result = check_if_uuid_exists(create_agent_database, 'uuid-9999')
    assert result is None


def test_insert_new_agent(create_agent_database: str):
    """Verify the functionality of the 'insert_new_agent' function.

    Inserts a new agent into the database and checks that the agent is
    correctly retrievable by its name. Ensures that all the details match
    what was inserted.

    Args:
        create_agent_database (str): Path with the database for testing.

    Assertions:
        Asserts that inserted agent is correctly initilized in the database.
    """
    insert_new_agent(create_agent_database, 'uuid-91011', 'key-91011', 'Agent3')

    result = check_if_agent_exists(create_agent_database, 'Agent3')
    assert result is not None
    assert result[1] == 'uuid-91011'
    assert result[2] == 'key-91011'
    assert result[3] == 'Agent3'
