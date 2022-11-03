'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: A Wazuh cluster is a group of Wazuh managers that work together to enhance the availability
       and scalability of the service. These tests will check the agent enrollment in a multi-server
       environment and how the agent manages the connections to the servers depending on their status.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-authd
    - wazuh-remoted

os_platform:
    - linux
    - windows


os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/registering/index.html

tags:
    - enrollment
'''
import os
import pytest
from time import sleep

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from wazuh_testing.agent import CLIENT_KEYS_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH

# Marks

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORTS = [1514, 1516, 1517]
AUTHD_PORT = 1515
SERVER_HOSTS = ['testServer1', 'testServer2', 'testServer3']

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
"""
How does this test work:

    - PROTOCOL: tcp/udp
    - CLEAN_KEYS: whatever start with an empty client.keys file or not
    - SIMULATOR_NUMBERS: Number of simulator to be instantiated, this should match wazuh_conf.yaml
    - SIMULATOR MODES: for each number of simulator will define a list of "stages"
    that defines the state that remoted simulator should have in that state
    Length of the stages should be the same for all simulators.
    Authd simulator will only accept one enrollment for stage
    - LOG_MONITOR_STR: (list of lists) Expected string to be monitored in all stages
"""
metadata = [
    {
        # 1. 3 Servers - (TCP/UDP) protocol all servers will refuse the connection to remoted but will accept enrollment
        # Starting with an empty clients.key.
        # We should verify that the agent tries to connect and enroll to each one of them.
        'ID': 'refuse_remoted_accept_enrollment',
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS': True,
        'SIMULATOR_NUMBER': 3,
        'SIMULATOR_MODES': {
            0: ['REJECT'],
            1: ['REJECT'],
            2: ['REJECT'],
            'AUTHD': ['ACCEPT'],
        },
        'LOG_MONITOR_STR': [
            [  # Stage 1
                f'Trying to connect to server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f'Requesting a key from server: {SERVER_HOSTS[0]}',
                f'Trying to connect to server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f'Requesting a key from server: {SERVER_HOSTS[1]}',
                f'Trying to connect to server ([{SERVER_HOSTS[2]}]:{REMOTED_PORTS[2]}',
                f'Requesting a key from server: {SERVER_HOSTS[2]}'
            ]
        ]
    },
    {
        # 2. 3 Servers - (TCP/UDP) protocol.
        # First server only has enrollment available and third server only has remoted available.
        # Agent should enroll to the first server and connect to the third one.
        'ID': 'only_enrollment_and_only_remoted',
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS': True,
        'SIMULATOR_NUMBER': 3,
        'SIMULATOR_MODES': {
            0: ['REJECT', 'REJECT'],
            1: ['REJECT', 'REJECT'],
            2: ['CONTROLLED_ACK', 'CONTROLLED_ACK'],
            'AUTHD': ['ACCEPT', 'REJECT'],
        },
        'LOG_MONITOR_STR': [
            [  # Stage 1 - Enroll to first server
                f'Requesting a key from server: {SERVER_HOSTS[0]}',
                f'Valid key received',
                f'Trying to connect to server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f"Connected to enrollment service at '[{SERVER_ADDRESS}]:{AUTHD_PORT}",
            ],
            [  # Stage 2 - Pass second server and connect to third
                f'Trying to connect to server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f'Requesting a key from server: {SERVER_HOSTS[1]}',
                f'Trying to connect to server ([{SERVER_HOSTS[2]}]:{REMOTED_PORTS[2]}',
                f'Connected to the server ([{SERVER_HOSTS[2]}]:{REMOTED_PORTS[2]}',
                f"Received message: '#!-agent ack '"
            ]
        ]
    },
    {
        # 3. 3 Server - TCP protocol. Agent should enroll and connect to first server,
        # and then the first server will disconnect, agent should connect to the second server with the same key
        'ID': 'server_down_fallback_tcp',
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS': True,
        'SIMULATOR_NUMBER': 3,
        'SIMULATOR_MODES': {
            0: ['CONTROLLED_ACK', 'CLOSE'],
            1: ['CONTROLLED_ACK', 'CONTROLLED_ACK'],
            2: ['CONTROLLED_ACK', 'CONTROLLED_ACK'],
            'AUTHD': ['ACCEPT', 'REJECT'],
        },
        'LOG_MONITOR_STR': [
            [  # Stage 1 - Enroll and connect to first server
                f'Requesting a key from server: {SERVER_HOSTS[0]}',
                f"Connected to enrollment service at '[{SERVER_ADDRESS}]:{AUTHD_PORT}'",
                f'Valid key received',
                f'Trying to connect to server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f'Connected to the server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f"Received message: '#!-agent ack '"
            ],
            [
                # f'Lost connection with manager. Setting lock.',
                f'Trying to connect to server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f'Trying to connect to server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f'Connected to the server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f"Received message: '#!-agent ack '",
            ]
        ]
    },
    {
        # 4. 3 Server - UDP protocol. Agent should enroll and connect to first server,
        # and then the first server will disconnect, agent should try to enroll to the first server again and then
        # after failure, move to the second server and connect.
        'ID': 'server_down_fallback_udp',
        'PROTOCOL': 'udp',
        'CLEAN_KEYS': True,
        'SIMULATOR_NUMBER': 3,
        'SIMULATOR_MODES': {
            0: ['CONTROLLED_ACK', 'REJECT'],
            1: ['CONTROLLED_ACK', 'CONTROLLED_ACK'],
            2: ['CONTROLLED_ACK', 'CONTROLLED_ACK'],
            'AUTHD': ['ACCEPT', 'REJECT'],
        },
        'LOG_MONITOR_STR': [
            [  # Stage 1 - Enroll and connect to first server
                f'Requesting a key from server: {SERVER_HOSTS[0]}',
                f"Connected to enrollment service at '[{SERVER_ADDRESS}]:{AUTHD_PORT}'",
                f'Valid key received',
                f'Trying to connect to server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f'Connected to the server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f"Received message: '#!-agent ack '"
            ],  # Stage 2 - Enroll and connect to second server after failed attempts to connect with server 1
            [
                f'Server unavailable. Setting lock.',
                f'Requesting a key from server: {SERVER_HOSTS[0]}',
                f'Trying to connect to server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f'Connected to the server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f"Received message: '#!-agent ack '",
            ]
        ]
    },
    {
        # 5. 3 Servers / (TCP/UDP) protocol only the last one is available.
        # Agent should enroll and connect to the last server.
        'ID': 'only_one_server_available',
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS': False,
        'SIMULATOR_NUMBER': 3,
        'SIMULATOR_MODES': {
            0: ['CLOSE', 'CLOSE', 'CLOSE'],
            1: ['CLOSE', 'CLOSE', 'CLOSE'],
            2: ['CONTROLLED_ACK', 'CONTROLLED_ACK', 'CONTROLLED_ACK'],
            'AUTHD': ['REJECT', 'REJECT', 'ACCEPT'],
        },
        'LOG_MONITOR_STR': [
            [
                f'Trying to connect to server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f"Unable to connect to '[{SERVER_ADDRESS}]:{REMOTED_PORTS[0]}",
            ],
            [
                f'Trying to connect to server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f"Unable to connect to '[{SERVER_ADDRESS}]:{REMOTED_PORTS[1]}",
            ],
            [
                f"Connected to enrollment service at '[{SERVER_ADDRESS}]:{AUTHD_PORT}'",
                f"Received message: '#!-agent ack '"
            ]
        ]
    },
    {
        # 6. 3 Servers / (TCP/UDP) protocol. Server 1 is available but it disconnects, 2 and 3 are not responding.
        # Agent on disconnection should try server 2 and 3 and go back to 1.
        'ID': 'unique_available_server_disconnects',
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS': False,
        'SIMULATOR_NUMBER': 3,
        'SIMULATOR_MODES': {
            0: ['CONTROLLED_ACK', 'CLOSE', 'CONTROLLED_ACK'],
            1: ['CLOSE', 'CLOSE', 'CLOSE'],
            2: ['CLOSE', 'CLOSE', 'CLOSE'],
            'AUTHD': ['ACCEPT', 'ACCEPT', 'ACCEPT'],
        },
        'LOG_MONITOR_STR': [
            [
                f'Trying to connect to server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}',
                f"Connected to the server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}",
                f"Received message: '#!-agent ack '",
            ],
            [
                f'Trying to connect to server ([{SERVER_HOSTS[1]}]:{REMOTED_PORTS[1]}',
                f"Unable to connect to '[{SERVER_ADDRESS}]:{REMOTED_PORTS[1]}",
            ],
            [
                f'Trying to connect to server ([{SERVER_HOSTS[2]}]:{REMOTED_PORTS[2]}',
                f"Unable to connect to '[{SERVER_ADDRESS}]:{REMOTED_PORTS[2]}",
                f"Connected to the server ([{SERVER_HOSTS[0]}]:{REMOTED_PORTS[0]}",
                f'Server responded. Releasing lock.',
                f"Received message: '#!-agent ack '"
            ]
        ]
    },
]

case_ids = [x['ID'] for x in metadata]

# metadata = metadata[:] # 0,2 Run only one test

params = [
    {
        'SERVER_ADDRESS_1': SERVER_HOSTS[0],
        'SERVER_ADDRESS_2': SERVER_HOSTS[1],
        'SERVER_ADDRESS_3': SERVER_HOSTS[2],
        'REMOTED_PORT_1': REMOTED_PORTS[0],
        'REMOTED_PORT_2': REMOTED_PORTS[1],
        'REMOTED_PORT_3': REMOTED_PORTS[2],
        'PROTOCOL': test['PROTOCOL']
    } for test in metadata]

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

log_monitor_paths = []

receiver_sockets_params = []

monitored_sockets_params = []

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

authd_server = AuthdSimulator(SERVER_ADDRESS, key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)
remoted_servers = []

tcase_timeout = 120


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=case_ids)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope="module")
def add_hostnames(request):
    """Add to OS hosts file, names and IP's of test servers."""
    HOSTFILE_PATH = os.path.join(os.environ['SystemRoot'], 'system32', 'drivers', 'etc', 'hosts') \
        if os.sys.platform == 'win32' else '/etc/hosts'
    hostfile = None
    with open(HOSTFILE_PATH, "r") as f:
        hostfile = f.read()
    for server in SERVER_HOSTS:
        if server not in hostfile:
            with open(HOSTFILE_PATH, "a") as f:
                f.write(f'{SERVER_ADDRESS}  {server}\n')
    yield

    with open(HOSTFILE_PATH, "w") as f:
        f.write(hostfile)


@pytest.fixture(scope="module")
def configure_authd_server(request, get_configuration):
    """Initialize multiple simulated remoted connections.

    Args:
        get_configuration (fixture): Get configurations from the module.
    """
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)
    authd_server.start()
    authd_server.set_mode('REJECT')
    global remoted_servers
    for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
        remoted_servers.append(RemotedSimulator(server_address=SERVER_ADDRESS, remoted_port=REMOTED_PORTS[i],
                                                protocol=get_configuration['metadata']['PROTOCOL'],
                                                mode='CONTROLLED_ACK', client_keys=CLIENT_KEYS_PATH))
        # Set simulator mode for that stage
        if get_configuration['metadata']['SIMULATOR_MODES'][i][0] != 'CLOSE':
            remoted_servers[i].set_mode(get_configuration['metadata']['SIMULATOR_MODES'][i][0])

    yield
    # hearing on enrollment server
    for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
        remoted_servers[i].stop()
    remoted_servers = []
    authd_server.shutdown()


@pytest.fixture(scope="function")
def set_authd_id(request):
    """Set agent id to 101 in the authd simulated connection."""
    authd_server.agent_id = 101


@pytest.fixture(scope="function")
def clean_keys(request, get_configuration):
    """Clear the client.key file used by the simulated remoted connections.

    Args:
        get_configuration (fixture): Get configurations from the module.
    """
    if get_configuration['metadata'].get('CLEAN_KEYS', True):
        truncate_file(CLIENT_KEYS_PATH)
        sleep(1)
    else:
        with open(CLIENT_KEYS_PATH, 'w') as f:
            f.write("100 ubuntu-agent any TopSecret")
        sleep(1)


def restart_agentd():
    """Restart agentd daemon with debug mode active."""
    control_service('stop', daemon="wazuh-agentd")
    truncate_file(LOG_FILE_PATH)
    control_service('start', daemon="wazuh-agentd", debug_mode=True)


# Tests
def wait_until(x, log_str):
    """Callback function to wait for a message in a log file.

    Args:
        x (str): String containing message.
        log_str (str): Log file string.
    """
    return x if log_str in x else None


# @pytest.mark.parametrize('test_case', [case for case in tests])
@pytest.mark.skip(reason='https://github.com/wazuh/wazuh-qa/issues/3536')
def test_agentd_multi_server(add_hostnames, configure_authd_server, set_authd_id, clean_keys, configure_environment,
                             get_configuration):
    '''
    description: Check the agent's enrollment and connection to a manager in a multi-server environment.
                 Initialize an environment with multiple simulated servers in which the agent is forced to enroll
                 under different test conditions, verifying the agent's behavior through its log files.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - add_hostnames:
            type: fixture
            brief: Adds to the 'hosts' file the names and the IP addresses of the testing servers.
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - set_authd_id:
            type: fixture
            brief: Sets the agent id to '101' in the 'wazuh-authd' simulated connection.
        - clean_keys:
            type: fixture
            brief: Clears the 'client.keys' file used by the simulated remote connections.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.

    assertions:
        - Agent without keys. Verify that all servers will refuse the connection to the 'wazuh-remoted' daemon
          but will accept enrollment. The agent should try to connect and enroll each of them.
        - Agent without keys. Verify that the first server only has enrollment available, and the third server
          only has the 'wazuh-remoted' daemon available. The agent should enroll in the first server and
          connect to the third one.
        - Agent without keys. Verify that the agent should enroll and connect to the first server, and then
          the first server will disconnect. The agent should connect to the second server with the same key.
        - Agent without keys. Verify that the agent should enroll and connect to the first server, and then
          the first server will disconnect. The agent should try to enroll in the first server again,
          and then after failure, move to the second server and connect.
        - Agent with keys. Verify that the agent should enroll and connect to the last server.
        - Agent with keys. Verify that the first server is available, but it disconnects, and the second and
          third servers are not responding. The agent on disconnection should try the second and third servers
          and go back finally to the first server.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases are found in the test module and include parameters for
                       the environment setup, the requests to be made, and the expected result.

    expected_output:
        - r'Requesting a key from server'
        - r'Valid key received'
        - r'Trying to connect to server'
        - r'Connected to enrollment service'
        - r'Received message'
        - r'Server responded. Releasing lock.'
        - r'Unable to connect to enrollment service at'

    tags:
        - simulator
        - ssl
        - keys
    '''
    log_monitor = FileMonitor(LOG_FILE_PATH)

    for stage in range(0, len(get_configuration['metadata']['LOG_MONITOR_STR'])):

        authd_server.set_mode(get_configuration['metadata']['SIMULATOR_MODES']['AUTHD'][stage])
        authd_server.clear()

        for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
            # Set simulator mode for that stage
            if get_configuration['metadata']['SIMULATOR_MODES'][i][stage] != 'CLOSE':
                remoted_servers[i].set_mode(get_configuration['metadata']['SIMULATOR_MODES'][i][stage])
            else:
                remoted_servers[i].stop()

        if stage == 0:
            # Restart at beginning of test
            restart_agentd()

        for index, log_str in enumerate(get_configuration['metadata']['LOG_MONITOR_STR'][stage]):
            try:
                log_monitor.start(timeout=tcase_timeout, callback=lambda x: wait_until(x, log_str))
            except TimeoutError:
                assert False, f"Expected message '{log_str}' never arrived! Stage: {stage+1}, message number: {index+1}"

        for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
            # Clean after every stage
            if get_configuration['metadata']['SIMULATOR_MODES'][i][stage] == 'CLOSE':
                remoted_servers[i].start()

        authd_server.clear()
    return
