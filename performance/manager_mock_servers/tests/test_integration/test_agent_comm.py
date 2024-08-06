import pytest
import httpx
import sqlite3
import os
import time
from fastapi import status
from fastapi.testclient import TestClient
from requests.auth import HTTPBasicAuth
from manager_mock_servers.manager_services.agent_comm_mock.agent_comm_mock import app, set_database_path, router_version, set_report_file,  database_directory, stateless_events, statefull_events
from manager_mock_servers.utils.agent_database_handler import create_agents_database, insert_new_agent


TESTING_VERSION = "/v33"
app.include_router(router_version, prefix=TESTING_VERSION)

client = TestClient(app)
DATABASE_NAME = 'agents.db'

UUID = '019126aa-16e1-7009-af24-2d64875104bc'
KEY = 'key'
NAME = 'agent1'

# Setup agents.db
@pytest.fixture(scope="session", autouse=True)
def set_versioning():
    pass

# Setup agents.db
@pytest.fixture(scope="module", autouse=True)
def configure_report_file(tmp_path_factory):
    temporal_dir = tmp_path_factory.mktemp('metrics')
    report_file = os.path.join(temporal_dir, 'metrics.csv')
    set_report_file(report_file)

    yield report_file

# Setup agents.db
@pytest.fixture(scope="module")
def init_db(tmp_path_factory):
    """Set up and tear down the test database."""
    temporal_dir = tmp_path_factory.mktemp('agents_database')
    db_path = os.path.join(temporal_dir, DATABASE_NAME)
    create_agents_database(temporal_dir)
    set_database_path(db_path)

    yield db_path

    # Teardown
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE agents')
    conn.commit()
    conn.close()
    os.remove(db_path)

# Setup agents.db
@pytest.fixture(scope="module")
def mock_agent_register(init_db):
    """Testing."""
    db_path = init_db
    insert_new_agent(db_path, UUID, KEY, NAME)


@pytest.fixture
def auth_token(init_db, mock_agent_register):
    """Obtain an authentication token."""
    # /v33/authentication
    response = client.post(f"{TESTING_VERSION}/authentication",
                           json={"uuid": UUID, "key": KEY}
                           )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()

    yield response.json().get('token')


def test_token(auth_token):
    """Test that the authentication token is valid."""
    assert auth_token is not None


def test_stateless_event(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(f'{TESTING_VERSION}/events/stateless', json={
        "events": [
            {"id": 1, "data": "test_data"}
        ]
    },
    headers=headers)
    assert response.status_code == 200
    assert response.json() == {'message': 'Event received'}


def test_stateful_event(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(f'{TESTING_VERSION}/events/stateful', json={
        "events": [
            {"id": 1, "data": "test_data"}
        ]
    },
    headers=headers)
    assert response.status_code == 200
    assert response.json() == {'message': 'Event is being processed and will be persisted'}


def test_metrics(configure_report_file):
    expected_statefull_evens = {

    }
    expected_stateless_evens = {

    }
    assert statefull_events
    assert stateless_events


def test_metrics_file(configure_report_file):
    with TestClient(app) as client:
        time.sleep(10)
        assert os.path.exists(configure_report_file)