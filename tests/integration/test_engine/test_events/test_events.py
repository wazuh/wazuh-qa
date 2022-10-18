import os
import pytest
import socket
import struct
import shutil

from wazuh_testing.tools.configuration import get_test_cases_data
from wazuh_testing.modules.engine import event_monitor as evm
from wazuh_testing.modules import engine


# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_engine_logs.yaml')

# Engine events configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)

# vars
events = t1_configuration_metadata[0]['events']
expected_outputs = t1_configuration_metadata[0]['engine_outputs']


@pytest.fixture(scope='module')
def create_kvdb():
    if not os.path.isdir(engine.KVDB_PATH):
        print('INFO: Creating the KVDB database')
        command = f"{engine.ENGINE_BUILD_PATH}/main kvdb -p {engine.OUTPUT_FOLDER} -n win-security-categorization " \
                  f"-i {engine.KVDB_WIN_INPUT} -t json"
        print(f"INFO: Running {command}")

        engine.run_local_command_printing_output(command)
    else:
        print(f"INFO: The KVDB already exists in {engine.KVDB_PATH}")

    yield

    print('INFO: Removing KVDB files')
    shutil.rmtree('/tmp/win-security-categorization/', ignore_errors=False, onerror=None)

@pytest.fixture(scope='module')
def start_engine():
    socket_data = 'tcp:localhost:5054'
    environment = 'demo-environment'
    command = f"{engine.ENGINE_BUILD_PATH}/main run -f {engine.ASSETS_PATH} -e {socket_data} -t 1 -k " \
              f"{engine.OUTPUT_FOLDER} --environment {environment}"
    print(f"INFO: Running {command}")

    engine.run_engine(command)

    yield

    # kill the engine subprocess
    engine.kill_engine()

@pytest.fixture(scope='function')
def send_events_to_the_engine(event):
    # engine.send_event_to_engine(event)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect(('127.0.0.1', 5054))

    # msg format -> queue:location_str:msg
    msg_formatted = engine.QUEUE + ':' + engine.LOCATION + ':' + event
    msg_tam = len(msg_formatted)
    msg_tam_little_endian = struct.pack('<I', msg_tam)

    # the engine's tcpEndpoint expects the following format:
    # header(len(msg) in little endian) + queue:location_str:msg
    encoded_msg = msg_tam_little_endian + msg_formatted.encode()
    client_socket.send(encoded_msg)
    print(f"INFO: Sending encoded event: {encoded_msg}")

@pytest.mark.tier(level=0)
@pytest.mark.parametrize('event, expected_output', zip(events, expected_outputs))
def test_engine_events(create_kvdb, start_engine, send_events_to_the_engine, expected_output):
    print(f"expected_output: {type(expected_output)}")
    print(f"waiting for {expected_output[2:len(expected_output)-1]}")
    evm.check_engine_json_event(event=expected_output[2:len(expected_output)-1])
