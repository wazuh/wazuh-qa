"""Testing."""
import os

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from manager_mock_servers.manager_services.manager_server_mock.manager_server_mock import (
    app,
    connect_db,
    set_database_path,
)

client = TestClient(app)

DATABASE_NAME = 'agents.db'


@pytest.fixture(scope="session", autouse=True)
def init_db(tmp_path_factory):
    """Testing."""
    temporal_dir = tmp_path_factory.mktemp('agents_database')
    db_path = os.path.join(temporal_dir, DATABASE_NAME)
    set_database_path(db_path)

    # Create tables
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT NOT NULL,
            credential TEXT NOT NULL,
            name TEXT NOT NULL
        )
    ''')

    yield db_path

    # Teardown
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DROP TABLE agents')
    conn.commit()
    conn.close()


@pytest.fixture
def auth_token():
    """Testing."""
    username = "your_username"
    password = "your_password"
    response = client.post("/authentication",
                           json={"user": username, "password": password}
                           )

    assert response.status_code == status.HTTP_200_OK
    assert response.json

    yield response.json().get('token')


def test_token(auth_token):
    """Testing."""
    assert auth_token is not None


def test_agents(auth_token):
    """Testing."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/agents",
                            json={"uuid": "testingid", "key": "key", "name": "agent_name"},
                            headers=headers
                           )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'message': 'Agent was correctly registered'}
