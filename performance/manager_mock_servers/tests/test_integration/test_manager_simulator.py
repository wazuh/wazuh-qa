import pytest
import subprocess
import tempfile
import os
import shutil
import socket
import time
import sqlite3


simulate_manager_parameters = {
    'manager_api_port': 55001,
    'agent_comm_api_port': 2901,
    'server_path': tempfile.mkdtemp(),
    'report_path': os.path.join('/tmp', 'metrics.csv')
}

@pytest.fixture(scope='function', params=[simulate_manager_parameters])
def launch_manager_simulator(request):
    params = request.param
    manager_api_port = params['manager_api_port']
    agent_comm_api_port = params['agent_comm_api_port']
    server_path = params['server_path']
    report_path = params['report_path']

    # Start the manager simulator as a subprocess
    process = subprocess.Popen([
        'run-mock-managers-services',  # Replace with the actual script to run the simulation
        '--manager-api-port', str(manager_api_port),
        '--agent-comm-api-port', str(agent_comm_api_port),
        '--server-path', server_path,
        '--report-path', report_path
    ])

    # Wait for the services to start
    time.sleep(5)

    yield {
        'manager_api_port': manager_api_port,
        'agent_comm_api_port': agent_comm_api_port,
        'server_path': server_path,
        'report_path': report_path,
        'process': process
    }

    # Clean up after test
    process.terminate()
    process.wait()
    shutil.rmtree(server_path)
    # os.remove(report_path)

def test_simulate_manager(launch_manager_simulator):
    params = launch_manager_simulator
    manager_api_port = params['manager_api_port']
    agent_comm_api_port = params['agent_comm_api_port']
    server_path = params['server_path']
    report_path = params['report_path']

    # Ensure the services are running on the provided ports
    def is_port_open(port, host='localhost'):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            return result == 0

    assert is_port_open(manager_api_port), f"Service is not running on port {manager_api_port}"
    assert is_port_open(agent_comm_api_port), f"Service is not running on port {agent_comm_api_port}"

    # Check if database and credentials are set up
    db_file = os.path.join(server_path, 'agents.db')
    assert os.path.exists(db_file), "Database file does not exist"

    # Optional: Check database content
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        assert len(tables) > 0, "Database is empty"

    # Check if credentials were created
    key_file = os.path.join(server_path, 'certs', 'private_key.pem')
    cert_file = os.path.join(server_path, 'certs', 'cert.pem')
    assert os.path.exists(key_file), "Private key file does not exist"
    assert os.path.exists(cert_file), "Certificate file does not exist"
