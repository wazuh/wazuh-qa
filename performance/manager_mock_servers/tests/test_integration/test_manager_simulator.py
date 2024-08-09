# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Test simulate_manager script."""
import os
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
from typing import Generator

import pytest
from pytest import FixtureRequest

simulate_manager_parameters = {
    'manager_api_port': 55001,
    'agent_comm_api_port': 2901,
    'server_path': tempfile.mkdtemp(),
    'report_path': os.path.join('/tmp', 'metrics.csv')
}


def is_port_open(port: int, host: str = 'localhost') -> bool:
    """Check if a given port on a host is open.

    Parameters:
        port (int): The port number to check.
        host (str): The host name or IP address. Defaults to 'localhost'.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        return result == 0


@pytest.fixture(scope='function', params=[simulate_manager_parameters])
def launch_manager_simulator(request: FixtureRequest) -> Generator:
    """Fixture to launch the manager simulator.

    This fixture starts a manager simulator as a subprocess with parameters
    defined in `simulate_manager_parameters`. It waits for the services to start
    before yielding the parameters and process handle to the test function. After
    the test completes, it terminates the process and performs cleanup.

    Args:
        request (FixtureRequest): The pytest request object which provides access
                                  to the parameters.

    Yields:
        dict: A dictionary containing:
              - 'manager_api_port': Port for manager API.
              - 'agent_comm_api_port': Port for agent communication API.
              - 'server_path': Path to the server directory.
              - 'report_path': Path to the report file.
              - 'process': The subprocess handle for the mock manager simulator.
    """
    timeout_service_started = 5
    params = request.param
    manager_api_port = params['manager_api_port']
    agent_comm_api_port = params['agent_comm_api_port']
    server_path = params['server_path']
    report_path = params['report_path']

    process = subprocess.Popen([
        'simulate-manager',
        '--manager-api-port', str(manager_api_port),
        '--agent-comm-api-port', str(agent_comm_api_port),
        '--server-path', server_path,
        '--report-path', report_path
    ])

    time.sleep(timeout_service_started)

    yield {
        'manager_api_port': manager_api_port,
        'agent_comm_api_port': agent_comm_api_port,
        'server_path': server_path,
        'report_path': report_path,
        'process': process
    }

    process.terminate()
    process.wait()
    shutil.rmtree(server_path)


def test_simulate_manager(launch_manager_simulator: dict):
    """Test that verifies the manager simulator is running and correctly set up.

    This test function checks the following:
    - The manager API and agent communication API services are running on the expected ports.
    - The database file exists and contains tables.
    - The required credentials (private key and certificate) are present in the server directory.

    Args:
        launch_manager_simulator (dict): Dictionary of parameters and process handle
                                         yielded by the `launch_manager_simulator` fixture.
    Assertions:
        Asserts that expected ports are being used by the mockers
        Asserts that the credentials is correctly generated in expected path
        Asserts that the database is correctly generated in the expected path
        Asserts that the metrics file is correctly generated in the expected path
    """
    params = launch_manager_simulator
    manager_api_port = params['manager_api_port']
    agent_comm_api_port = params['agent_comm_api_port']
    server_path = params['server_path']
    report_path = params['report_path']

    assert is_port_open(manager_api_port), f"Service is not running on port {manager_api_port}"
    assert is_port_open(agent_comm_api_port), f"Service is not running on port {agent_comm_api_port}"

    db_file = os.path.join(server_path, 'agents.db')
    assert os.path.exists(db_file), "Database file does not exist"

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        assert len(tables) > 0, "Database is empty"

    key_file = os.path.join(server_path, 'certs', 'private_key.pem')
    cert_file = os.path.join(server_path, 'certs', 'cert.pem')
    assert os.path.exists(key_file), "Private key file does not exist"
    assert os.path.exists(cert_file), "Certificate file does not exist"

    assert os.path.exists(report_path)
