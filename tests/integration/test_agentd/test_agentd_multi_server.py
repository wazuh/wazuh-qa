# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from time import sleep
# Marks

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORTS = [1514, 1516, 1517]
SERVER_HOSTS = ['testServer1', 'testServer2', 'testServer3']

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
r"""
How does this test work:
- PROTOCOL: tcp/udp
- CLEAN_KEYS: whetever start with an empty client.keys file or not
- SIMULATOR_NUMBERS: Number of simulator to be instantiated, this should match wazuh_conf.yaml
- SIMULATOR MODES: for each number of simulator will define a list of "stages" that defines the state that the remoted simulator should have in that state
Lenght of the stages should be the same for all simulators. Authd simulator will only accept one enrollment for stage
- LOG_MONITOR_STR: (list of lists) Expected string to be monitored in all stages
"""
metadata = [
    {
        # 1. 3 Servers - (TCP/UDP) protocol all servers will refuse the connection to remoted but will accept enrollment. 
        # Starting with an empty clients.key. We should verify that the agent tries to connect and enroll to each one of them.
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS' : True,
        'SIMULATOR_NUMBER' : 3,
        'SIMULATOR_MODES' : {
            0: ['REJECT'],
            1: ['REJECT'],
            2: ['REJECT'],
            'AUTHD' : ['ACCEPT'],
        },
        'LOG_MONITOR_STR' : [
            [ # Stage 1
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f'Starting enrollment process to server: {SERVER_HOSTS[0]}/{SERVER_ADDRESS}',
                f'Trying to connect to server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f'Starting enrollment process to server: {SERVER_HOSTS[1]}/{SERVER_ADDRESS}',
                f'Trying to connect to server ({SERVER_HOSTS[2]}/{SERVER_ADDRESS}:{REMOTED_PORTS[2]}',
                f'Starting enrollment process to server: {SERVER_HOSTS[2]}/{SERVER_ADDRESS}'
            ]
        ]
    },
    {
        # 2. 3 Servers - (TCP/UDP) protocol. 
        # First server only has enrollment available and third server only has remoted available. Agent should enroll to the first server and connect to the third one.
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS' : True,
        'SIMULATOR_NUMBER' : 3,
        'SIMULATOR_MODES' : {
            0: ['REJECT', 'REJECT'],
            1: ['REJECT', 'REJECT'],
            2: ['CONTROLED_ACK', 'CONTROLED_ACK'],
            'AUTHD' : ['ACCEPT', 'REJECT'],
        },
        'LOG_MONITOR_STR' : [
            [ # Stage 1 - Enroll to first server
                f'Starting enrollment process to server: {SERVER_HOSTS[0]}',
                f'Valid key created. Finished',
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
            ],
            [ # Stage 2 - Pass second server and connect to third
                f'Starting enrollment process to server: {SERVER_HOSTS[0]}',
                f'Trying to connect to server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f'Starting enrollment process to server: {SERVER_HOSTS[1]}/{SERVER_ADDRESS}',
                f'Trying to connect to server ({SERVER_HOSTS[2]}/{SERVER_ADDRESS}:{REMOTED_PORTS[2]}',
                f'Connected to the server ({SERVER_HOSTS[2]}/{SERVER_ADDRESS}:{REMOTED_PORTS[2]}',
                f"Received message: '#!-agent ack '"
            ]
        ]
    },
    {
        # 3. 3 Server - TCP protocol. Agent should enroll and connect to first server, and then the first server will disconnect, 
        # agent should connect to the second server with the same key
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS' : True,
        'SIMULATOR_NUMBER' : 3,
        'SIMULATOR_MODES' : {
            0: ['CONTROLED_ACK', 'CLOSE'],
            1: ['CONTROLED_ACK', 'CONTROLED_ACK'],
            2: ['CONTROLED_ACK', 'CONTROLED_ACK'],
            'AUTHD' : ['ACCEPT', 'REJECT'],
        },
        'LOG_MONITOR_STR' : [
            [ # Stage 1 - Enroll and connect to first server
                f'Starting enrollment process to server: {SERVER_HOSTS[0]}',
                f'Valid key created. Finished',
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f'Connected to the server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f"Received message: '#!-agent ack '"
            ],
            [ 
                f'Lost connection with manager. Setting lock.',
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f'Trying to connect to server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f'Connected to the server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f"Received message: '#!-agent ack '",
            ]
        ]
    },
    {
        # 4. 3 Server - UDP protocol. Agent should enroll and connect to first server, 
        # and then the first server will disconnect, agent should try to enroll to the first server again and then after failure, move to the second server and connect.
        'PROTOCOL': 'udp',
        'CLEAN_KEYS' : True,
        'SIMULATOR_NUMBER' : 3,
        'SIMULATOR_MODES' : {
            0: ['CONTROLED_ACK', 'REJECT'],
            1: ['CONTROLED_ACK', 'CONTROLED_ACK'],
            2: ['CONTROLED_ACK', 'CONTROLED_ACK'],
            'AUTHD' : ['ACCEPT', 'REJECT'],
        },
        'LOG_MONITOR_STR' : [
            [ # Stage 1 - Enroll and connect to first server
                f'Starting enrollment process to server: {SERVER_HOSTS[0]}',
                f'Valid key created. Finished',
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f'Connected to the server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f"Received message: '#!-agent ack '"
            ],
            [ 
                f'Server unavailable. Setting lock.',
                f'Starting enrollment process to server: {SERVER_HOSTS[0]}',
                f'Trying to connect to server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f'Connected to the server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f"Received message: '#!-agent ack '",
            ]
        ]
    },
    {
        # 5. 3 Servers / (TCP/UDP) protocol only the last one is available. Agent should enroll and connect to the last server.
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS' : False,
        'SIMULATOR_NUMBER' : 3,
        'SIMULATOR_MODES' : {
            0: ['CLOSE', 'CLOSE', 'CLOSE'],
            1: ['CLOSE', 'CLOSE', 'CLOSE'],
            2: ['CONTROLED_ACK', 'CONTROLED_ACK', 'CONTROLED_ACK'],
            'AUTHD' : ['REJECT', 'REJECT', 'ACCEPT'],
        },
        'LOG_MONITOR_STR' : [
            [
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f"Unable to connect to '{SERVER_ADDRESS}': 'Connection refused'",
            ],
            [ 
                f'Trying to connect to server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f"Unable to connect to '{SERVER_ADDRESS}': 'Connection refused'",
            ],
            [ 
                f'Connected to the server ({SERVER_HOSTS[2]}/{SERVER_ADDRESS}:{REMOTED_PORTS[2]}',
                f"Received message: '#!-agent ack '"
            ]
        ]
    },
    {
        # 6. 3 Servers / (TCP/UDP) protocol. Server 1 is available but it disconnects, 2 and 3 are not responding. 
        # Agent on disconnection should try server 2 and 3 and go back to 1.
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS' : False,
        'SIMULATOR_NUMBER' : 3,
        'SIMULATOR_MODES' : {
            0: ['CONTROLED_ACK', 'CLOSE', 'CONTROLED_ACK'],
            1: ['CLOSE', 'CLOSE', 'CLOSE'],
            2: ['CLOSE', 'CLOSE', 'CLOSE'],
            'AUTHD' : ['ACCEPT', 'ACCEPT', 'ACCEPT'],
        },
        'LOG_MONITOR_STR' : [
            [
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f'Connected to the server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f"Received message: '#!-agent ack '",
            ],
            [ 
                f'Trying to connect to server ({SERVER_HOSTS[1]}/{SERVER_ADDRESS}:{REMOTED_PORTS[1]}',
                f"Unable to connect to '{SERVER_ADDRESS}': 'Connection refused'",
            ],
            [ 
                f'Trying to connect to server ({SERVER_HOSTS[2]}/{SERVER_ADDRESS}:{REMOTED_PORTS[2]}',
                f"Unable to connect to '{SERVER_ADDRESS}': 'Connection refused'",
                f'Connected to the server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f'Server responded. Releasing lock.',
                f"Received message: '#!-agent ack '"
            ]
        ]
    },
    {
        # 7. 3 Servers / (TCP/UDP) protocol. Server 1 and 2 have remoted availble but doesn't have authd,
        #  agent should enroll in 3rd server and then connect to the first.
        'PROTOCOL': 'tcp',
        'CLEAN_KEYS' : True,
        'SIMULATOR_NUMBER' : 3,
        'SIMULATOR_MODES' : {
            0: ['CONTROLED_ACK', 'CONTROLED_ACK'],
            1: ['CONTROLED_ACK', 'CONTROLED_ACK'],
            2: ['CLOSE', 'CLOSE'],
            'AUTHD' : ['REJECT', 'ACCEPT'],
        },
        'LOG_MONITOR_STR' : [
            [
                 f'Starting enrollment process to server: {SERVER_HOSTS[0]}',
                 f'Starting enrollment process to server: {SERVER_HOSTS[1]}',
            ],
            [
                f'Starting enrollment process to server: {SERVER_HOSTS[2]}',
                f'Valid key created. Finished',
                f'Trying to connect to server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f'Connected to the server ({SERVER_HOSTS[0]}/{SERVER_ADDRESS}:{REMOTED_PORTS[0]}',
                f"Received message: '#!-agent ack '",
            ],
        ]
    },
]

#metadata = [metadata[4]] # Run only one test

params = [
{
    'SERVER_ADDRESS_1': SERVER_HOSTS[0],
    'SERVER_ADDRESS_2': SERVER_HOSTS[1],
    'SERVER_ADDRESS_3': SERVER_HOSTS[2],
    'REMOTED_PORT_1': REMOTED_PORTS[0],
    'REMOTED_PORT_2': REMOTED_PORTS[1],
    'REMOTED_PORT_3': REMOTED_PORTS[2],
    'PROTOCOL' : test['PROTOCOL']
} for test in metadata]

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

log_monitor_paths = []

receiver_sockets_params = []

monitored_sockets_params = []

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

authd_server = AuthdSimulator()
remoted_servers = []

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="module")
def add_hostnames(request):
    HOSTFILE_PATH = '/etc/hosts' 
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
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)
    authd_server.start()
    authd_server.set_mode('REJECT')
    global remoted_servers
    for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
        remoted_servers.append(RemotedSimulator(server_address=SERVER_ADDRESS, remoted_port=REMOTED_PORTS[i], protocol=get_configuration['metadata']['PROTOCOL'], mode='CONTROLED_ACK'))
    yield
    #hearing on enrollment server   
    for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):  
        remoted_servers[i].stop()
    remoted_servers = []
    authd_server.shutdown()

@pytest.fixture(scope="function")
def set_authd_id(request):
    authd_server.agent_id = 101    

@pytest.fixture(scope="function")
def clean_keys(request, get_configuration):
    client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
    if get_configuration['metadata'].get('CLEAN_KEYS', True):
        truncate_file(client_keys_path)
        sleep(1)
    else:
        with open(client_keys_path, 'w') as f:
            f.write("100 ubuntu-agent any TopSecret")
        sleep(1)

@pytest.fixture(scope="function")
def clean_logs(request):
    truncate_file(LOG_FILE_PATH)


@pytest.fixture(scope="function")
def restart_agentd(request):
    control_service('stop', daemon="ossec-agentd")
    control_service('start', daemon="ossec-agentd", debug_mode=True)

# Tests
      
#@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agentd_multi_server(add_hostnames, configure_authd_server, set_authd_id, clean_keys, clean_logs, configure_environment, restart_agentd, get_configuration):
  
    #start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    #hearing on enrollment server   

    for stage in range(0, len(get_configuration['metadata']['LOG_MONITOR_STR'])):

        authd_server.set_mode(get_configuration['metadata']['SIMULATOR_MODES']['AUTHD'][stage])
        authd_server.clear()
            

        for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
            # Set simulator mode for that stage
            if get_configuration['metadata']['SIMULATOR_MODES'][i][stage] != 'CLOSE':
                remoted_servers[i].set_mode(get_configuration['metadata']['SIMULATOR_MODES'][i][stage])
            else:
                remoted_servers[i].stop()

        for index, log_str in enumerate(get_configuration['metadata']['LOG_MONITOR_STR'][stage]):
            try:
                log_monitor.start(timeout=120, callback=lambda x: x if log_str in x else None) 
            except TimeoutError as err:
                raise AssertionError(f'Expected message {log_str} never arrived! Stage: {stage}, message number: {index}')     
        

        for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
            # Clean after every stage
            if get_configuration['metadata']['SIMULATOR_MODES'][i][stage] == 'CLOSE':
                remoted_servers[i].start()

        authd_server.clear()
    return

    