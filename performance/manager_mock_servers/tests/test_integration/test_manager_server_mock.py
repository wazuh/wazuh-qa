"""Testing."""
import os
import pytest
import sqlite3
from fastapi import status
from fastapi.testclient import TestClient

from manager_mock_servers.manager_services.manager_server_mock.manager_server_mock import (
    app,
    set_database_path,
)

client = TestClient(app)

DATABASE_NAME = 'agents.db'


@pytest.fixture(scope="session", autouse=True)
def init_db(tmp_path_factory):
    """Set up and tear down the test database."""
    temporal_dir = tmp_path_factory.mktemp('agents_database')
    db_path = os.path.join(temporal_dir, DATABASE_NAME)
    set_database_path(db_path)

    # Create tables
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT NOT NULL,
            credential TEXT NOT NULL,
            name TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

    yield db_path

    # Teardown
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE agents')
    conn.commit()
    conn.close()
    os.remove(db_path)


@pytest.fixture(scope="function")
def clean_database(init_db):
    conn = sqlite3.connect(init_db)
    cursor = conn.cursor()

    cursor.execute(f'DELETE FROM agents;')
    cursor.execute(f'DELETE FROM sqlite_sequence WHERE name="agents";')
    conn.commit()
    conn.close()



@pytest.fixture
def auth_token():
    """Obtain an authentication token."""
    username = "your_username"
    password = "your_password"
    response = client.post("/authentication",
                           json={"user": username, "password": password}
                           )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()

    yield response.json().get('token')


def test_token(auth_token):
    """Test that the authentication token is valid."""
    assert auth_token is not None


def test_agents(auth_token, clean_database):
    """Test successful agent registration."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/agents",
                            json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key", "name": "agent_name"},
                            headers=headers
                           )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'message': 'Agent was correctly registered'}


def test_invalid_token(clean_database):
    """Test response with an invalid authentication token."""
    headers = {"Authorization": "Bearer invalidtoken"}
    response = client.post("/agents",
                            json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key", "name": "agent_name"},
                            headers=headers
                           )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {'detail': 'Invalid JWT token'}


def test_missing_field(auth_token, clean_database):
    """Test agent registration with missing fields."""

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


def test_invalid_data(auth_token, clean_database):
    """Test agent registration with invalid data."""
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Invalid 'uuid'
    response = client.post("/agents",
                            json={"uuid": "INVALID-UUID", "key": "key", "name": "agent_name"},
                            headers=headers
                           )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert 'Input should be a valid UUID' in response.text

    # Invalid 'name'
    response = client.post("/agents",
                            json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73bc", "key": "key", "name": ""},  # Empty name
                            headers=headers
                           )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert 'Missing parameters' in response.text


def test_duplicate_agent_uuid(auth_token, clean_database):
    """Test attempting to register an agent with duplicate UUID."""
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
                            json={"uuid": "019121d5-712b-7bc4-8645-3124bc8d73be", "key": "key2", "name": "agent_name2"},
                            headers=headers
                           )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json() == {'error': 'Agent with this credential already registered', "uuid": "019121d5-712b-7bc4-8645-3124bc8d73be"}



def test_duplicate_agent_name(auth_token, clean_database):
    """Test attempting to register an agent with duplicate UUID."""
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
