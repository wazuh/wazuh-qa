import pytest
import httpx
import sqlite3
import os
from fastapi import status
from fastapi.testclient import TestClient
from requests.auth import HTTPBasicAuth
from manager_mock_servers.manager_services.agent_comm_mock.agent_comm_mock import app, set_database_path, connect_db





@pytest.fixture(scope="session", autouse=True)
def init_db():
    # Create an in-memory SQLite database
    db_path = "/tmp/database"
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

    yield '/tmp/database'

    # Teardown
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DROP TABLE agents')
    conn.commit()
    conn.close()


def test_example():
    pass