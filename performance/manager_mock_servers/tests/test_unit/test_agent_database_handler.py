import pytest
import os
import sqlite3
from manager_mock_servers.utils.agent_database_handler import insert_new_agent, check_if_agent_exists, check_if_uuid_exists, \
    create_agents_database

from _pytest.tmpdir import TempPathFactory
from typing import Protocol


@pytest.fixture
def temp_db_path(tmpdir):
    """Fixture to provide a temporary path for a test SQLite database.

    Uses the pytest 'tmpdir' fixture to create a temporary directory for database storage.
    Returns the path as a string.
    """
    db_path = tmpdir.mkdir("db")
    return str(db_path)


@pytest.fixture
def create_agent_database(tmp_path_factory: TempPathFactory):
    """Fixture to create a new SQLite database for testing with the 'agents' table.

    Uses the pytest 'tmp_path_factory' fixture to create a temporary database directory.
    Calls the 'create_agents_database' function to initialize the database.
    Yields the path to the created database file.
    """
    agent_database_path = tmp_path_factory.mktemp('db')
    db_path = create_agents_database(agent_database_path)

    yield db_path


def test_create_agents_database(create_agent_database: Protocol):
    """Verify that the agents database is created with the correct table structure.

    Asserts that the database file exists and that the 'agents' table contains the
    expected columns: 'id', 'uuid', 'credential', and 'name'.
    """
    assert os.path.exists(create_agent_database)

    # Check that the table was created
    with sqlite3.connect(create_agent_database) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(agents);")
        columns = [column[1] for column in cursor.fetchall()]
        expected_columns = ['id', 'uuid', 'credential', 'name']
        assert set(columns) == set(expected_columns)

def test_check_if_agent_exists(create_agent_database: Protocol):
    """Verify the functionality of the 'check_if_agent_exists' function.

    Inserts a new agent into the database and checks that the agent can be
    correctly retrieved by its name. Also verifies that a non-existent agent
    returns None.
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

def test_check_if_uuid_exists(create_agent_database: Protocol):
    """Verify the functionality of the 'check_if_uuid_exists' function.

    Inserts a new agent into the database and checks that the UUID can be
    correctly retrieved. Also verifies that a non-existent UUID returns None.
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

def test_insert_new_agent(create_agent_database: Protocol):
    """Verify the functionality of the 'insert_new_agent' function.

    Inserts a new agent into the database and checks that the agent is
    correctly retrievable by its name. Ensures that all the details match
    what was inserted.
    """
    insert_new_agent(create_agent_database, 'uuid-91011', 'key-91011', 'Agent3')

    result = check_if_agent_exists(create_agent_database, 'Agent3')
    assert result is not None
    assert result[1] == 'uuid-91011'
    assert result[2] == 'key-91011'
    assert result[3] == 'Agent3'
