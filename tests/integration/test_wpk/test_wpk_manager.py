# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
import socket
import subprocess
import struct
import threading
import time

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

UPGRADE_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'upgrade')
TASK_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'task')
SERVER_ADDRESS = 'localhost'
WPK_REPOSITORY_4x = 'packages.wazuh.com/4.x/wpk/'
CRYPTO = "aes"
CHUNK_SIZE = 16384

cases = [
    # 1. Single Agent - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'sha_list' : ['dca785b264b134f4c474d4fdf029f0f2c70d6bfc'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True]
        }
    },
    # 2. Single Agent - faliure
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'sha_list' : ['dca785b264b134f4c474d4fdf029f0f2c70d6bfc'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [2],
            'status': ['Failed'],
            'upgrade_notification': [True]
        }
    },
    # 3. Multiple Agents
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 3,
            'protocol': 'tcp',
            'agents_os': ['debian7', 'ubuntu12.04', 'debian10'],
            'sha_list' : ['dca785b264b134f4c474d4fdf029f0f2c70d6bfc', 'INVALIDSHA', 'dca785b264b134f4c474d4fdf029f0f2c70d6bfc'],
            'upgrade_exec_result' : ['0', '0', '0'],
            'upgrade_script_result' : [0, 0, 2],
            'status': ['Done', 'Failed', 'Failed'],
            'upgrade_notification': [True, False, True]
        }
    }
]


params = [ case['params'] for case in cases ]
metadata = [ case['metadata'] for case in cases ]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

#configurations = configurations[2:]

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


def test_wpk_manager(get_configuration, configure_environment, restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    expected_status = metadata['status']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    for index, agent in enumerate(agents):
        agent.set_wpk_variables(metadata['sha_list'][index], metadata['upgrade_exec_result'][index], metadata['upgrade_notification'][index], metadata['upgrade_script_result'][index])

        injector = Injector(sender, agent)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    # Give time for registration key to be avilable and send a few heartbeats
    time.sleep(30)

    data = { 
        'command' : 'upgrade', 
        'agents' : [int(x.id) for x in agents] 
    }
    response = send_message(data, UPGRADE_SOCKET)
    task_ids = [item.get('task_id') for item in response]

    for index, task_id in enumerate(task_ids):
        data = [{ 
            "module": "api", 
            "command" : 'task_result', 
            "task_id" : task_id 
        }]
        response = send_message(data, TASK_SOCKET)
        retries = 0
        while (response[0]['status'] == 'In progress') and (retries < 10):
            time.sleep(10)
            response = send_message(data, TASK_SOCKET)
            retries += 1
        assert expected_status[index] == response[0]['status'], f'Upgrade Status did not match expected! Expected {expected_status[index]} obtained {response[0]["status"]}'

    return
