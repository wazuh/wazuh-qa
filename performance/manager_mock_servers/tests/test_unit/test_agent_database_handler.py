# test_db_manager.py

import pytest
import os
import sqlite3
from manager_mock_servers.utils.agent_database_handler import insert_new_agent, check_if_agent_exists, check_if_uuid_exists, \
    create_agents_database

@pytest.fixture
def temp_db_path(tmpdir):
    """Fixture to provide a temporary database path for testing."""
    db_path = tmpdir.mkdir("db")
    return str(db_path)


@pytest.fixture
def create_agent_database(tmp_path_factory):
    agent_database_path = tmp_path_factory.mktemp('db')
    db_path = create_agents_database(agent_database_path)

    yield db_path


def test_create_agents_database(create_agent_database):
    """Test that the database and table are created correctly."""
    assert os.path.exists(create_agent_database)

    # Check that the table was created
    with sqlite3.connect(create_agent_database) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(agents);")
        columns = [column[1] for column in cursor.fetchall()]
        expected_columns = ['id', 'uuid', 'credential', 'name']
        assert set(columns) == set(expected_columns)

def test_check_if_agent_exists(create_agent_database):
    """Test the check_if_agent_exists function."""
    insert_new_agent(create_agent_database, 'uuid-1234', 'key-1234', 'Agent1')

    result = check_if_agent_exists(create_agent_database, 'Agent1')
    assert result is not None
    assert result[1] == 'uuid-1234'
    assert result[2] == 'key-1234'
    assert result[3] == 'Agent1'

    # Check for a non-existent agent
    result = check_if_agent_exists(create_agent_database, 'NonExistentAgent')
    assert result is None

def test_check_if_uuid_exists(create_agent_database):
    """Test the check_if_uuid_exists function."""
    insert_new_agent(create_agent_database, 'uuid-5678', 'key-5678', 'Agent2')

    result = check_if_uuid_exists(create_agent_database, 'uuid-5678')
    assert result is not None
    assert result[1] == 'uuid-5678'
    assert result[2] == 'key-5678'
    assert result[3] == 'Agent2'

    # Check for a non-existent UUID
    result = check_if_uuid_exists(create_agent_database, 'uuid-9999')
    assert result is None

def test_insert_new_agent(create_agent_database):
    """Test the insert_new_agent function."""
    insert_new_agent(create_agent_database, 'uuid-91011', 'key-91011', 'Agent3')

    result = check_if_agent_exists(create_agent_database, 'Agent3')
    assert result is not None
    assert result[1] == 'uuid-91011'
    assert result[2] == 'key-91011'
    assert result[3] == 'Agent3'
