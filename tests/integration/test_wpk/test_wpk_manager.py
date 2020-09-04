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

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

UPGRADE_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'upgrade')
TASK_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'task')
UPGRADE_PATH = os.path.join(WAZUH_PATH, 'var', 'upgrade')
SERVER_ADDRESS = 'localhost'
MANAGER_VERSION = 'v4.1.0'
WPK_REPOSITORY_4x = 'packages.wazuh.com/4.x/wpk/'
WPK_REPOSITORY_3x = 'packages.wazuh.com/wpk/'
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
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'expected_response' : 'Success'
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
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [2],
            'status': ['Failed'],
            'upgrade_notification': [True],
            'expected_response' : 'Success'
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
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37', 'INVALIDSHA', 'c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0', '0', '0'],
            'upgrade_script_result' : [0, 0, 2],
            'status': ['Done', 'Failed', 'Failed'],
            'upgrade_notification': [True, False, True],
            'expected_response' : 'Success'
        }
    },
    # 4. Upgrading an agent to a version higher than the manager - Fail
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
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'version' : 'v4.1.0', 'force_upgrade': 0 },
            'expected_response' : 'Upgrading an agent to a version higher than the manager requires the force flag.'
        }
    },
    # 5. Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'version' : 'v3.5.0', 'force_upgrade': 0 },
            'expected_response' : 'Current agent version is greater or equal.'
        }
    },
    # 6. The version of the WPK does not exist in the repository - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'version' : 'v4.1.0', 'force_upgrade': 0 },
            'expected_response' : 'The version of the WPK does not exist in the repository.'
        }
    },
    # 7. The repository is not reachable - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : 'bad.repository.url',
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'version' : 'v4.1.0', 'force_upgrade': 0 },
            'expected_response' : 'The repository is not reachable.'
        }
    },
    # 8. The WPK for this platform is not available - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['mojave'],
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'expected_response' : 'The WPK for this platform is not available.'
        }
    },
    # 9. Already updated - Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'],
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'expected_response' : 'Current agent version is greater or equal.'
        }
    },
    # 10. Already updated with force=1 - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'],
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'force_upgrade': 1 },
            'expected_response' : 'Success'
        }
    },
    # 11. Already updated with force=1 - Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'], #debian8 have v4.0.0 agent version
            'sha_list' : ['c4efef55ab95ca195fd2197e5c59f6546fdf8d37'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'force_upgrade': 0 },
            'expected_response' : 'Current agent version is greater or equal.'
        }
    },
    # 12 Upgrade Legacy - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'sha_list' : ['af4d150d58500f79ccb71012057f3ad796017a68'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Legacy'],
            'upgrade_notification': [False],
            'message_params': {'version' : 'v3.13.1'},
            'expected_response' : 'Success'
        }
    },
    # XX. Custom - File not found
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'], #debian8 have v4.0.0 agent version
            'sha_list' : ['af4d150d58500f79ccb71012057f3ad796017a68'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Legacy'],
            'upgrade_notification': [False],
            'message_params': {'file_path' : 'invalid/path/to.wpk'},
            'expected_response' : 'The WPK file does not exist.',
            'command' : 'upgrade_custom'
        }
    },
    # XX. Upgrade an agent that is begin upgraded - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE
        },
        'metadata' : {
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'], #debian8 have v4.0.0 agent version
            'sha_list' : ['dca785b264b134f4c474d4fdf029f0f2c70d6bfc'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [False],
            'expected_response' : 'Upgrade procedure could not start. Agent already upgrading.',
            'first_attempt' : 'In progress'
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
    clean_logs()
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


def clean_logs():
    truncate_file(LOG_FILE_PATH)


def wait_download(line):
    if "DEBUG: Downloading " in line:
        return line
    return None

def remove_wpk_package():
    for file in os.scandir(UPGRADE_PATH):
        if file.name.endswith('.wpk'):
            os.unlink(file.path)


def test_wpk_manager(get_configuration, configure_environment, restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    expected_status = metadata['status']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    log_monitor = FileMonitor(LOG_FILE_PATH)

    for index, agent in enumerate(agents):
        agent.set_wpk_variables(metadata['sha_list'][index], metadata['upgrade_exec_result'][index], metadata['upgrade_notification'][index], metadata['upgrade_script_result'][index])

        injector = Injector(sender, agent)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    # Give time for registration key to be avilable and send a few heartbeats
    time.sleep(30)

    command = ''
    if metadata.get('command') and metadata.get('command') == 'upgrade_custom':
        command = 'upgrade_custom'
    else :
        command = 'upgrade'
    
    data = { 
        'command' : command, 
        'agents' : [int(x.id) for x in agents] 
    }

    if metadata.get('message_params'):
        data['params'] = metadata.get('message_params')

    # remove wpk if need check http or version
    if metadata.get('checks') and ( 'use_http' in metadata.get('checks') or 'version' in metadata.get('checks')):
        remove_wpk_package()
        
    response = send_message(data, UPGRADE_SOCKET)

    if metadata.get('checks'):
        # Checking version in logs
        try:
            log_monitor.start(timeout=60, callback=wait_download)
        except TimeoutError as err:
            raise AssertionError("Download wpk log tooks too much!")

        last_log = log_monitor.result()
        if 'use_http' in metadata.get('checks'):
            if metadata.get('message_params').get('use_http') == 1:
                assert "'http://" in last_log, "Use http protocol did not match expected! Expected 'http://'"
            elif metadata.get('message_params').get('use_http') == 0:
                assert "'https://" in last_log, "Use http protocol did not match expected! Expected 'https://'"
            else:
                assert "'https://" in last_log, "Use http protocol did not match expected! Expected 'https://'"
        
        if 'version' in metadata.get('checks'):
            if metadata.get('message_params').get('version'):
                assert metadata.get('message_params').get('version') in last_log, f'Versions did not match expected! Expected {metadata.get("message_params").get("version")}'
            else :
                assert MANAGER_VERSION in last_log, f'Versions did not match expected! Expected {MANAGER_VERSION}'
    
    if metadata.get('first_attempt'):
        #Chech that result of first attempt is Success
        assert 'Success' == response[0]['data'], f'First upgrade response did not match expected! Expected {metadata.get("expected_response")} obtained {response[0]["data"]}'

        repeat_message = data
        #Continue with the validations of first attempt
        task_ids = [item.get('task_id') for item in response]
        for index, task_id in enumerate(task_ids):
            data = [{ 
                "module": "api", 
                "command" : 'task_result', 
                "task_id" : task_id 
            }]
            response = send_message(data, TASK_SOCKET)
            retries = 0
            while (response[0]['status'] != metadata.get('first_attempt')) and (retries < 10):
                time.sleep(10)
                response = send_message(data, TASK_SOCKET)
                retries += 1
            assert metadata.get('first_attempt') == response[0]['status'], f'First upgrade Status did not match expected! Expected {metadata.get("first_attempt")} obtained {response[0]["status"]}'
        
        #send upgrade request again
        response = send_message(repeat_message, UPGRADE_SOCKET)

    if metadata.get('expected_response') == 'Success':
        #Chech that result is expected
        assert metadata.get('expected_response') == response[0]['data'], f'Upgrade response did not match expected! Expected {metadata.get("expected_response")} obtained {response[0]["data"]}'

        #Continue with the test validations
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
    else:
        assert metadata.get('expected_response') == response[0]['data'], f'Upgrade response did not match expected! Expected {metadata.get("expected_response")} obtained {response[0]["data"]}'

    return
