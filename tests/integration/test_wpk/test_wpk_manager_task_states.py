'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Agents can be upgraded remotely. This upgrade is performed by the manager which
        sends each registered agent a WPK (Wazuh signed package) file that contains the files
        needed to upgrade the agent to the new version. These tests ensure, the behaviour of
        the WPK upgrade on the manager side, in case of the manager stopped before finishing
        the upgrade.

components:
    - wpk

targets:
    - manager

daemons:
    - wazuh-monitord
    - wazuh-remoted
    - wazuh-modulesd
    - wazuh-db

os_platform:
    - linux

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
    - https://documentation.wazuh.com/current/user-manual/agents/remote-upgrading/upgrading-agent.html

pytest_args:
    - wpk_version: Specify the version to upgrade
    - wpk_package_path: Specify the path to the wpk package

tags:
    - wpk
'''
import json
import os
import socket
import struct
import time

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.agent_simulator import Sender, Injector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing import global_parameters

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

UPGRADE_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'upgrade')
TASK_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'task')
SERVER_ADDRESS = 'localhost'
WPK_REPOSITORY_4x = global_parameters.wpk_package_path[0]
CRYPTO = "aes"
CHUNK_SIZE = 16384
TASK_TIMEOUT = '15m'
MAX_THREADS = 8

cases = [
    # 0. In queue -> Cancelled after manager restart
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT,
            'MAX_THREADS': 1
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 2,
            'protocol': 'tcp',
            'agents_os': ['debian7', 'debian7'],
            'agents_version': ['v3.11.3', 'v3.11.3'],
            'stage_disconnect': ['lock_restart', None],
            'first_status': ['Updating', 'In queue'],
            'expected_response': 'Success',
            'status': ['Updating', 'Task cancelled since the manager was restarted'],
            'upgrade_after_change_name': False
        }
    },
    # 1. Updating -> Timeout after manager restart
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': 60,
            'MAX_THREADS': 1
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': ['write'],
            'first_status': ['Updating'],
            'expected_response': 'Success',
            'status': ['Timeout reached while waiting for the response from the agent'],
            'upgrade_after_change_name': False
        }
    },
    # 2. In queue -> New task after manager restart and change node
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT,
            'MAX_THREADS': 1
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 2,
            'protocol': 'tcp',
            'agents_os': ['debian7', 'debian7'],
            'agents_version': ['v3.11.3', 'v3.11.3'],
            'stage_disconnect': ['lock_restart', None],
            'first_status': ['Updating', 'In queue'],
            'expected_response': 'Success',
            'status': ['Updating', 'In queue'],
            'upgrade_after_change_name': True,
            'change_node_name': True,
            'new_expected_response': [f'Upgrade procedure could not start. ' \
                                      f'Agent already upgrading', 'Success']
        }
    },
    # 3. No create new task after manager restart and change node
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT,
            'MAX_THREADS': 1
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': ['write'],
            'first_status': ['Updating'],
            'expected_response': 'Success',
            'status': ['Updating'],
            'change_node_name': True,
            'upgrade_after_change_name': True,
            'new_expected_response': [f'Upgrade procedure could not start. ' \
                                      f'Agent already upgrading', 'Success']
        }
    },
    # 4. Timeout -> New task after manager restart and change node
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': 60,
            'MAX_THREADS': 1
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': ['write'],
            'first_status': ['Updating'],
            'expected_response': 'Success',
            'status': ['Timeout reached while waiting for the response from the agent'],
            'change_node_name': True,
            'upgrade_after_change_name': True,
            'new_expected_response': ['Success']
        }
    }
]

params = [case['params'] for case in cases]
metadata = [case['metadata'] for case in cases]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params, metadata=metadata)

# List where the agents objects will be stored
agents = []


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope="function")
def restart_service():
    control_service('restart')

    yield


def send_message(data_object, socket_path):
    upgrade_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upgrade_sock.connect(socket_path)
    msg_bytes = json.dumps(data_object).encode()
    upgrade_sock.send(struct.pack("<I", len(msg_bytes)) + msg_bytes)
    size = struct.unpack("<I", upgrade_sock.recv(4, socket.MSG_WAITALL))[0]
    response = upgrade_sock.recv(size, socket.MSG_WAITALL)
    return json.loads(response.decode())


def overwrite_node_name(value):
    new_content = ''

    ossec_conf = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')

    with open(ossec_conf, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line
            if '<node_name>' in line:
                new_line = f'<node_name>{value}</node_name>\n'
            new_content += new_line

    with open(ossec_conf, 'w') as f:
        f.write(new_content)


@pytest.mark.skip(reason="Blocked by issue wazuh-qa#2203, when is fixed we can enable this test again")
def test_wpk_manager_task_states(get_configuration, configure_environment,
                                 restart_service, configure_agents):
    '''
    description: Agents can be upgraded remotely. This upgrade is performed by the manager which
                  sends each registered agent a WPK (Wazuh signed package) file that contains the files
                  needed to upgrade the agent to the new version. These tests ensure, the behaviour of
                  the WPK upgrade on the manager side, in case of the manager stopped before finishing
                  the upgrade.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_service:
            type: fixture
            brief: Restart Wazuh manager.
        - configure_agents:
            type: fixture
            brief: Configure all simulated agents.

    input_description: Test case metadata

    assertions:
        - Verify that the first attemp is success
        - Verify the upgrade status matches the expected
        - Verify the upgrade status after restarting
        - Verify the upgrade response matches the expected

    expected_output:
        - r'Upgrade process result'

    tags:
        - wpk
    '''
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    first_status = metadata['first_status']
    expected_status = metadata['status']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    change_node_name = metadata.get('change_node_name')
    upgrade_after_change_name = metadata.get('upgrade_after_change_name')
    new_expected_response = metadata.get('new_expected_response')
    injectors = []

    for index, agent in enumerate(agents):
        agent.set_wpk_variables(stage_disconnect=metadata['stage_disconnect'][index])
        injector = Injector(sender, agent)
        injectors.append(injector)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    # If have params for test case add to the data to send
    if metadata.get('message_params'):
        data['parameters'].update(metadata.get('message_params'))

    # Give time for registration key to be available and send a few heartbeats
    time.sleep(40)

    agents_id = [int(x.id) for x in agents]
    task_ids = []
    for agent_id in agents_id:
        data = {
            'command': 'upgrade',
            'parameters': {'agents': [agent_id]}
        }

        # Send upgrade request
        response = send_message(data, UPGRADE_SOCKET)

        # Chech that result of first attempt is Success
        assert 'Success' == response['data'][0]['message'], \
            f'First upgrade response did not match expected! ' \
            f'Expected Success obtained {response["data"][0]["message"]}'

        task_ids += [item.get('agent') for item in response['data']]

    # Check initial task state
    for index, agent_id in enumerate(task_ids):
        data = {
            "origin": {
                "module": "api"
            },
            "command": 'upgrade_result',
            "parameters": {
                "agents": [agent_id]
            }
        }

        response = send_message(data, TASK_SOCKET)
        retries = 0
        while response['data'][0]['status'] != first_status[index] \
                and retries < 30:
            time.sleep(2)
            response = send_message(data, TASK_SOCKET)
            retries += 1

        assert first_status[index] == response['data'][0]['status'], \
            f'Upgrade status did not match expected! ' \
            f'Expected {first_status[index]} obtained ' \
            f'{response["data"][0]["status"]} at index {index}'

    for injector in injectors:
        injector.stop_receive()

    # Stop Manager
    control_service('stop')

    if change_node_name:
        overwrite_node_name('new_node_name')

    # Start manager again
    control_service('start')

    if upgrade_after_change_name:
        injectors = []
        sender = Sender(manager_address=SERVER_ADDRESS,
                        protocol=protocol)
        for index, agent in enumerate(agents):
            injector = Injector(sender, agent)
            injectors.append(injector)
            injector.run()
            if protocol == "tcp":
                sender = Sender(manager_address=SERVER_ADDRESS,
                                protocol=protocol)

    # Give time for registration key to be available and send a few heartbeats
    time.sleep(80)

    # Check task state after restart
    for index, agent_id in enumerate(task_ids):
        data = {
            "origin": {
                "module": "api"
            },
            "command": 'upgrade_result',
            "parameters": {
                "agents": [agent_id]
            }
        }

        response = send_message(data, TASK_SOCKET)
        retries = 0
        while response['data'][0]['status'] == 'Updating' \
                and retries < 30 and response['data'][0]['status'] \
                != expected_status[index]:
            time.sleep(5)
            response = send_message(data, TASK_SOCKET)
            retries += 1
        assert expected_status[index] == response['data'][0]['status'], \
            f'Upgrade status did not match expected! ' \
            f'Expected {expected_status[index]} obtained ' \
            f'{response["data"][0]["status"]} at index {index}'

    if upgrade_after_change_name:
        for agent_id in agents_id:
            data = {
                'command': 'upgrade',
                'parameters': {'agents': [agent_id]}
            }

            # Send upgrade request
            response = send_message(data, UPGRADE_SOCKET)

            # Chech that result of first attempt is Success
            assert new_expected_response[agents_id.index(agent_id)] == \
                   response['data'][0]['message'], \
                f'New upgrade response did not match expected! ' \
                f'Expected {new_expected_response} obtained ' \
                f'{response["data"][0]["message"]}'

        for injector in injectors:
            injector.stop_receive()

    if change_node_name:
        overwrite_node_name('node01')
