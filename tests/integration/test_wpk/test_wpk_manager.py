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
import hashlib
import requests

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
MANAGER_VERSION = 'v4.0.0'
WPK_REPOSITORY_4x = 'packages.wazuh.com/4.x/wpk/'
WPK_REPOSITORY_3x = 'packages.wazuh.com/wpk/'
CRYPTO = "aes"
CHUNK_SIZE = 16384
TASK_TIMEOUT = '15m'
global file_name, installer
file_name = ''
installer = ''

def set_debug_mode():
    local_int_conf_path=os.path.join(WAZUH_PATH,'etc', 'local_internal_options.conf')
    debug_line = 'wazuh_modules.debug=2\n'
    with  open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with  open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)

set_debug_mode()

cases = [
    # 1. Single Agent - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['VALIDSHA1'],
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
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['VALIDSHA1'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [2],
            'status': ['Failed'],
            'error_msg' : ['Upgrade procedure exited with error code.'],
            'upgrade_notification': [True],
            'expected_response' : 'Success'
        }
    },
    # 3. Single Agent - faliure SHA-1
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['INVALID'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Failed'],
            'error_msg' : ['Send verify sha1 error.'],
            'upgrade_notification': [False],
            'expected_response' : 'Success'
        }
    },
    # 4. Multiple Agents
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 3,
            'protocol': 'tcp',
            'agents_os': ['debian7', 'ubuntu12.04', 'debian10'],
            'disconnect' : [False, False, False],
            'sha_list' : ['VALIDSHA1', 'INVALIDSHA', 'VALIDSHA1'],
            'upgrade_exec_result' : ['0', '0', '0'],
            'upgrade_script_result' : [0, 0, 2],
            'status': ['Done', 'Failed', 'Failed'],
            'error_msg' : ['','Send verify sha1 error.','Upgrade procedure exited with error code.'],
            'upgrade_notification': [True, False, True],
            'expected_response' : 'Success'
        }
    },
    # 6. Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'version' : 'v3.5.0', 'force_upgrade': 0 },
            'expected_response' : 'Current agent version is greater or equal.'
        }
    },
    # 7. The version of the WPK does not exist in the repository - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [False],
            'message_params': {'version' : 'v4.55.55', 'force_upgrade': 0 },
            'expected_response' : 'The version of the WPK does not exist in the repository.'
        }
    },
    # 8. The repository is not reachable - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : 'bad.repository.url',
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [False],
            'message_params': {'version' : 'v4.1.0', 'force_upgrade': 0 },
            'expected_response' : 'The repository is not reachable.'
        }
    },
    # 9. The WPK for this platform is not available - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['mojave'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [False],
            'expected_response' : 'The WPK for this platform is not available.'
        }
    },
    # 10. Already updated - Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [False],
            'expected_response' : 'Current agent version is greater or equal.'
        }
    },
    # 11. Already updated with force=1 - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'],
            'disconnect' : [False],
            'sha_list' : ['VALIDSHA1'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [True],
            'message_params': {'force_upgrade': 1 },
            'expected_response' : 'Success'
        }
    },
    # 12. Already updated with force=0 - Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'], #debian8 have v4.0.0 agent version
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [False],
            'message_params': {'force_upgrade': 0 },
            'expected_response' : 'Current agent version is greater or equal.'
        }
    },
    # 13 Upgrade Legacy - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['VALIDSHA1'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Legacy'],
            'upgrade_notification': [False],
            'message_params': {'version' : 'v3.13.1'},
            'expected_response' : 'Success'
        }
    },
    # 14. Upgrade an agent that is begin upgraded - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'disconnect' : [False],
            'agents_os': ['debian7'],
            'sha_list' : ['VALIDSHA1'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Done'],
            'upgrade_notification': [False],
            'expected_response' : 'Upgrade procedure could not start. Agent already upgrading.',
            'first_attempt' : 'In progress'
        }
    },
    # 15. Single Agent with use_http = 1 - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['In progress'],
            'upgrade_notification': [True],
            'message_params': {'use_http' : 1},
            'checks' : ['use_http', 'version'],
            'expected_response' : 'Success'
        }
    },
    # 16. Single Agent with use_http = default - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['In progress'],
            'upgrade_notification': [True],
            'checks' : ['use_http', 'version'],
            'expected_response' : 'Success'
        }
    },
    # 17. Single Agent with use_http = 0 - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['In progress'],
            'message_params': {'use_http' : 1},
            'upgrade_notification': [True],
            'checks' : ['use_http', 'version'],
            'expected_response' : 'Success'
        }
    },
    # 18. Upgrade an agent that previus task is timeouted - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : '1m'
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['VALIDSHA1'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['In progress'],
            'upgrade_notification': [False],
            'expected_response' : 'Success',
            'first_attempt' : 'Timeout'
        }
    },
    # 19. Disconnect Agent - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'disconnect' : [True],
            'agents_os': ['debian7'],
            'sha_list' : ['VALIDSHA1'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Failed'],
            'upgrade_notification': [False], 
            'expected_response' : 'Success',
            'error_msg' : ['Send write file error.'],
        }
    },
    # 20. Change default chunk_size - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_4x,
            'CHUNK_SIZE' : 31111,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['VALIDSHA1'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['In progress'],
            'upgrade_notification': [True],
            'checks' : ['chunk_size'],
            'chunk_size' : 31111,
            'expected_response' : 'Success'
        }
    },
    # 21. Custom 
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['In progress'],
            'upgrade_notification': [False],
            'message_params': {'file_path' : 'wpk_test.wpk'},
            'checks' : ['wpk_name'],
            'expected_response' : 'Success',
            'command' : 'upgrade_custom'
        }
    },
    # 22. Custom - File not found
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['Failed'],
            'upgrade_notification': [False],
            'message_params': {'file_path' : 'invalid/path/to.wpk'},
            'error_msg' : ['The WPK file does not exist.'],
            'expected_response' : 'Success',
            'command' : 'upgrade_custom'
        }
    },
    # 23. Custom installer
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY' : WPK_REPOSITORY_3x,
            'CHUNK_SIZE' : CHUNK_SIZE,
            'TASK_TIMEOUT' : TASK_TIMEOUT
        },
        'metadata' : {
            'wpk_repository' : WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'disconnect' : [False],
            'sha_list' : ['NOT_NEED'],
            'upgrade_exec_result' : ['0'],
            'upgrade_script_result' : [0],
            'status': ['In progress'],
            'upgrade_notification': [False],
            'message_params': {'file_path' : 'wpk_test.wpk', 'installer' : 'custom_installer.sh'},
            'error_msg' : ['Not need'],
            'checks' : ['wpk_name'],
            'expected_response' : 'Success',
            'command' : 'upgrade_custom'
        }
    }
]


params = [ case['params'] for case in cases ]
metadata = [ case['metadata'] for case in cases ]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

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
    if "Downloading WPK file from: " in line:
        return line
    return None

def wait_chunk_size(line):
    if ("Sending message to agent: " in line) and ("com write" in line):
        return line
    return None

def wait_wpk_custom(line):
    global file_name, installer
    assert file_name == 'wpk_test.wpk','error filename'
    if ('Sending message to agent:' in line) and (f'com upgrade {file_name} {installer}' in line):
        return line
    return None


def remove_wpk_package():
    for file in os.scandir(UPGRADE_PATH):
        if file.name.endswith('.wpk'):
            os.unlink(file.path)

def create_wpk_custom_file(file):
    with open(file, 'wb') as f:
        f.seek(1024*128)
        f.write(b'\0')

def get_sha_list(metadata):
    agent_os = metadata['agents_os']
    protocol = 'https://'
    wpk_repo = metadata.get('wpk_repository')
    architecture = 'x86_64'

    if metadata.get('message_params') and metadata.get('message_params').get('version'):
        agent_version = metadata.get('message_params').get('version')
    else :
        agent_version = MANAGER_VERSION
    
    if metadata.get('message_params') and metadata.get('message_params').get('use_http'):
        protocol = 'http://' if metadata.get('message_params').get('use_http') == 1 else 'https://'
    
    # Generating file name
    wpk_file = "wazuh_agent_{0}_linux_{1}.wpk".format(agent_version, architecture)
    wpk_url = protocol + wpk_repo + "linux/" + architecture + "/" + wpk_file

    wpk_file_path = os.path.join(UPGRADE_PATH, wpk_file)
    
    if not os.path.exists(wpk_file_path):
        try:
            result = requests.get(wpk_url)
        except requests.exceptions.RequestException as e:
            pass
        
        if result.ok:
            with open(wpk_file_path, 'wb') as fd:
                for chunk in result.iter_content(chunk_size=128):
                    fd.write(chunk)        
        else:
            error = "Can't access to the WPK file in {}".format(wpk_url)
    
    # Get SHA1 file sum
    sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
    
    sha_list = []
    for sha in metadata['sha_list']:
        if sha == 'VALIDSHA1':
            sha_list.append(sha1hash)
        else:
            sha_list.append('INVALIDSHA1')
    
    return sha_list


def test_wpk_manager(get_configuration, configure_environment, restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    expected_status = metadata['status']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    log_monitor = FileMonitor(LOG_FILE_PATH)
    expected_error_msg = metadata.get('error_msg')
    sha_list = metadata.get('sha_list')

    if 'VALIDSHA1' in sha_list:
        sha_list = get_sha_list(metadata)
    
    command = 'upgrade'
    if metadata.get('command') == 'upgrade_custom':
        command = 'upgrade_custom'
        if not expected_error_msg or ('The WPK file does not exist.' not in expected_error_msg):
            global file_name, installer
            file_name = metadata.get('message_params').get('file_path')
            file = os.path.join(UPGRADE_PATH, file_name)
            create_wpk_custom_file(file)
            metadata['message_params']['file_path'] = file
            sha_list = [hashlib.sha1(open(file, 'rb').read()).hexdigest()]
        if metadata.get('message_params').get('installer'):
            installer = metadata.get('message_params').get('installer')
        else:
            installer = 'upgrade.sh'

    for index, agent in enumerate(agents):
        agent.set_wpk_variables(sha_list[index], metadata['upgrade_exec_result'][index], metadata['upgrade_notification'][index], metadata['upgrade_script_result'][index], metadata['disconnect'][index])

        injector = Injector(sender, agent)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    # Give time for registration key to be avilable and send a few heartbeats
    time.sleep(40)
    
    agents_id = [int(x.id) for x in agents]
    
    data = { 
        'command' : command, 
        'agents' : agents_id
    }

    # If have params for test case add to the data to send
    if metadata.get('message_params'):
        data['params'] = metadata.get('message_params')

    # remove wpk if need check http or version
    if metadata.get('checks') and ( 'use_http' in metadata.get('checks') or 'version' in metadata.get('checks')):
        remove_wpk_package()
    
    # Send upgrade request
    response = send_message(data, UPGRADE_SOCKET)

    if metadata.get('checks') and (('use_http' in metadata.get('checks')) or ('version' in metadata.get('checks'))):
        # Checking version or http in logs
        try:
            log_monitor.start(timeout=60, callback=wait_download)
        except TimeoutError as err:
            raise AssertionError("Download wpk log tooks too much!")

        last_log = log_monitor.result()
        if 'use_http' in metadata.get('checks'):
            if metadata.get('message_params') and metadata.get('message_params').get('use_http') and metadata.get('message_params').get('use_http') == 1:
                assert "'http://" in last_log, "Use http protocol did not match expected! Expected 'http://'"
            else:
                assert "'https://" in last_log, "Use http protocol did not match expected! Expected 'https://'"
        
        if 'version' in metadata.get('checks'):
            if metadata.get('message_params') and metadata.get('message_params').get('version'):
                assert metadata.get('message_params').get('version') in last_log, f'Versions did not match expected! Expected {metadata.get("message_params").get("version")}'
            else :
                assert MANAGER_VERSION in last_log, f'Versions did not match expected! Expected {MANAGER_VERSION}'
        #let time to download wpk
        time.sleep(60)
    
    if metadata.get('checks') and ('chunk_size' in metadata.get('checks')):
        # Checking version in logs
        try:
            log_monitor.start(timeout=60, callback=wait_chunk_size)
        except TimeoutError as err:
            raise AssertionError("Chunk size log tooks too much!")
            
        last_log = log_monitor.result()
        assert f'com write {metadata.get("chunk_size")}' in last_log, f'Chunk size did not match expected! Expected {metadata.get("chunk_size")} obtained {last_log}'
    
    if metadata.get('checks') and ('wpk_name' in metadata.get('checks')):
        # Checking version in logs
        try:
            log_monitor.start(timeout=120, callback=wait_wpk_custom)
        except TimeoutError as err:
            raise AssertionError("Custom wpk log tooks too much!")
            
        last_log = log_monitor.result()
        assert f'com upgrade {file_name} {installer}' in last_log, f'Wpk custom package did not match expected! Expected {metadata.get("message_params").get("file_path")} obtained {last_log}'
    
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
            time.sleep(30)
            response = send_message(data, TASK_SOCKET)
            retries = 0
            while (response[0]['status'] != metadata.get('first_attempt')) and (retries < 10) and (response[0]['status'] != metadata.get('first_attempt')):
                time.sleep(30)
                response = send_message(data, TASK_SOCKET)
                retries += 1
            assert metadata.get('first_attempt') == response[0]['status'], f'First upgrade status did not match expected! Expected {metadata.get("first_attempt")} obtained {response[0]["status"]}'
        
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
            time.sleep(30)
            response = send_message(data, TASK_SOCKET)
            retries = 0
            while (response[0]['status'] == 'In progress') and (retries < 10) and (response[0]['status'] != expected_status[index]):
                time.sleep(30)
                response = send_message(data, TASK_SOCKET)
                retries += 1
            assert expected_status[index] == response[0]['status'], f'Upgrade status did not match expected! Expected {expected_status[index]} obtained {response[0]["status"]} at index {index}'
            if expected_status[index] == 'Failed':
                assert expected_error_msg[index] == response[0]['error_msg'], f'Error msg did not match expected! Expected {expected_error_msg[index]} obtained {response[0]["error_msg"]} at index {index}'
    else:
        assert metadata.get('expected_response') == response[0]['data'], f'Upgrade response did not match expected! Expected {metadata.get("expected_response")} obtained {response[0]["data"]}'

    return
