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
import platform

from configobj import ConfigObj
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import global_parameters

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

UPGRADE_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'upgrade')
TASK_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'tasks', 'task')
UPGRADE_PATH = os.path.join(WAZUH_PATH, 'var', 'upgrade')
SERVER_ADDRESS = 'localhost'
WPK_REPOSITORY_4x = 'packages-dev.wazuh.com/trash/wpk/'
WPK_REPOSITORY_3x = 'packages.wazuh.com/wpk/'
CRYPTO = "aes"
CHUNK_SIZE = 16384
TASK_TIMEOUT = '15m'
global valid_sha1_list
valid_sha1_list = {}

if not global_parameters.wpk_version:
    raise Exception("The WPK package version must be defined by parameter. See README.md")
version_to_upgrade = global_parameters.wpk_version[0]

def get_current_version():
    if platform.system() == 'Linux':
        config_file_path = os.path.join(WAZUH_PATH, 'etc', 'ossec-init.conf')
        _config = ConfigObj(config_file_path)
        return _config['VERSION']
    return None

MANAGER_VERSION = get_current_version()

cases = [
    # 0. Single Agent - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [True],
            'expected_response': 'Success'
        }
    },
    # 1. Single Agent - faliure
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [2],
            'status': ['Error'],
            'error_msg': ['Upgrade procedure exited with error code'],
            'upgrade_notification': [True],
            'expected_response': 'Success'
        }
    },
    # 2. Single Agent - failure SHA-1
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['INVALID'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'error_msg': ['Send verify sha1 error'],
            'upgrade_notification': [False],
            'expected_response': 'Success'
        }
    },
    # 3. Multiple Agents
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 3,
            'protocol': 'tcp',
            'agents_os': ['debian7', 'ubuntu12.04', 'debian10'],
            'agents_version': ['v3.11.3','v3.11.3','v3.11.3'],
            'stage_disconnect': [None, None, None],
            'sha_list': ['VALIDSHA1', 'INVALIDSHA', 'VALIDSHA1'],
            'upgrade_exec_result': ['0', '0', '0'],
            'upgrade_script_result': [0, 0, 2],
            'status': ['Updated', 'Error', 'Error'],
            'error_msg': ['', 'Send verify sha1 error','Upgrade procedure exited with error code'],
            'upgrade_notification': [True, False, True],
            'expected_response': 'Success'
        }
    },
    # 4. Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_3x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [True],
            'message_params': {'version': 'v3.5.0', 'force_upgrade': False},
            'expected_response': 'Current agent version is greater or equal'
        }
    },
    # 5. The version of the WPK does not exist in the repository - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_3x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'upgrade_notification': [False],
            'status': ['Error'],
            'message_params': {'version': 'v4.55.55', 'force_upgrade': True},
            'error_msg': ['The version of the WPK does not exist in the repository'],
            'expected_response': 'Success'
        }
    },
    # 6. The repository is not reachable - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': 'bad.repository.url',
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'message_params': {'version': MANAGER_VERSION, 'force_upgrade': False},
            'error_msg': ['The repository is not reachable'],
            'expected_response': 'Success'
        }
    },
    # 7. The WPK for this platform is not available - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['mojave'],
            'agents_version': ['v3.11.0'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [False],
            'expected_response': 'The WPK for this platform is not available'
        }
    },
    # 8. Already updated - Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'],
            'agents_version': [version_to_upgrade],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [False],
            'expected_response': 'Current agent version is greater or equal'
        }
    },
    # 9. Upgrading an agent to a version higher than the manager - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_3x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'upgrade_notification': [False],
            'status': ['Error'],
            'message_params': {'version': 'v4.55.55', 'force_upgrade': False},
            'expected_response': 'Upgrading an agent to a version higher than the manager requires the force flag'
        }
    },
    # 10. Already updated with force=True - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'],
            'agents_version': [version_to_upgrade],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [True],
            'message_params': {'force_upgrade': True},
            'expected_response': 'Success'
        }
    },
    # 11. Already updated with force=False - Current agent version is greater or equal - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian8'],
            'agents_version': [version_to_upgrade],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [False],
            'message_params': {'force_upgrade': False},
            'expected_response': 'Current agent version is greater or equal'
        }
    },
    # 12 Upgrade Legacy - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_3x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Legacy upgrade: check the result manually since the agent cannot report the result of the task'],
            'upgrade_notification': [False],
            'message_params': {'version': 'v3.13.1'},
            'expected_response': 'Success'
        }
    },
    # 13. Upgrade an agent that is begin upgraded - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'stage_disconnect': [None],
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [False],
            'expected_response': 'Upgrade procedure could not start. Agent already upgrading',
            'first_attempt': 'Updating'
        }
    },
    # 14. Upgrade an agent that previous task's result is timeout - Success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': '1m'
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updating'],
            'upgrade_notification': [False],
            'expected_response': 'Success',
            'first_attempt': 'Timeout reached while waiting for the response from the agent'
        }
    },
    # 15. Disconnect Agent open error - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'stage_disconnect': ['open'],
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'expected_response': 'Success',
            'error_msg': ['Send open file error'],
        }
    },
    # 16. Disconnect Agent write error - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'stage_disconnect': ['write'],
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'expected_response': 'Success',
            'error_msg': ['Send write file error'],
        }
    },
    # 17. Disconnect Agent close error - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'stage_disconnect': ['close'],
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'expected_response': 'Success',
            'error_msg': ['Send close file error'],
        }
    },
    # 18. Disconnect Agent lock restart error- Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'stage_disconnect': ['lock_restart'],
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'expected_response': 'Success',
            'error_msg': ['Send lock restart error'],
        }
    },
    # 19. Disconnect Agent sha1 error - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'stage_disconnect': ['sha1'],
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'expected_response': 'Success',
            'error_msg': ['Send verify sha1 error'],
        }
    },
    # 20. Disconnect Agent upgrade error - Fail
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'stage_disconnect': ['upgrade'],
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'expected_response': 'Success',
            'error_msg': ['Send upgrade command error'],
        }
    },
    # 21. Change default chunk_size - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': 31111,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [True],
            'checks': ['chunk_size'],
            'chunk_size': 31111,
            'expected_response': 'Success'
        }
    },
    # 22. Custom
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_3x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updating'],
            'upgrade_notification': [False],
            'message_params': {'file_path': 'wpk_test.wpk'},
            'checks': ['wpk_name'],
            'expected_response': 'Success',
            'command': 'upgrade_custom'
        }
    },
    # 23. Custom - File not found
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_3x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Error'],
            'upgrade_notification': [False],
            'message_params': {'file_path': 'invalid/path/to.wpk'},
            'error_msg': ['The WPK file does not exist'],
            'expected_response': 'Success',
            'command': 'upgrade_custom'
        }
    },
    # 24. Custom installer
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_3x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_3x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['NOT_NEED'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updating'],
            'upgrade_notification': [False],
            'message_params': {'file_path': 'wpk_test.wpk', 'installer': 'custom_installer.sh'},
            'error_msg': ['Not need'],
            'checks': ['wpk_name'],
            'expected_response': 'Success',
            'command': 'upgrade_custom'
        }
    },
    # 25. Single Agent with use_http = True - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [True],
            'message_params': {'use_http': True},
            'checks': ['use_http', 'version'],
            'expected_response': 'Success'
        }
    },
    # 26. Single Agent with use_http = default - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'upgrade_notification': [True],
            'checks': ['use_http', 'version'],
            'expected_response': 'Success'
        }
    },
    # 27. Single Agent with use_http = False - success
    {
        'params': {
            'PROTOCOL': 'tcp',
            'WPK_REPOSITORY': WPK_REPOSITORY_4x,
            'CHUNK_SIZE': CHUNK_SIZE,
            'TASK_TIMEOUT': TASK_TIMEOUT
        },
        'metadata': {
            'wpk_repository': WPK_REPOSITORY_4x,
            'agents_number': 1,
            'protocol': 'tcp',
            'agents_os': ['debian7'],
            'agents_version': ['v3.11.3'],
            'stage_disconnect': [None],
            'sha_list': ['VALIDSHA1'],
            'upgrade_exec_result': ['0'],
            'upgrade_script_result': [0],
            'status': ['Updated'],
            'message_params': {'use_http': True},
            'upgrade_notification': [True],
            'checks': ['use_http', 'version'],
            'expected_response': 'Success'
        }
    }
]


params = [case['params'] for case in cases]
metadata = [case['metadata'] for case in cases]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

# List where the agents objects will be stored
agents = []


@pytest.fixture(scope="session")
def set_debug_mode():
    local_int_conf_path = os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
    debug_line = 'wazuh_modules.debug=2\n'
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)


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
    if 'Downloading WPK file from:' in line:
        return line
    return None


def wait_downloaded(line):
    if ('Download' in line) and ('finished' in line):
        return line
    return None


def wait_chunk_size(line):
    if ('Sending message to agent:' in line) and ('com write ' in line):
        return line
    return None


def wait_wpk_custom(line):
    if ('Sending message to agent:' in line) and ('com upgrade ' in line):
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
    global valid_sha1_list
    protocol = 'https://'
    wpk_repo = metadata.get('wpk_repository')
    architecture = 'x86_64'

    if metadata.get('message_params') and metadata.get('message_params').get('version'):
        agent_version = metadata.get('message_params').get('version')
    else:
        agent_version = MANAGER_VERSION

    if metadata.get('message_params') and metadata.get('message_params').get('use_http'):
        protocol = 'http://' if metadata.get('message_params').get('use_http') == True else 'https://'

    # Generating file name
    wpk_file = "wazuh_agent_{0}_linux_{1}.wpk".format(agent_version, architecture)
    wpk_url = protocol + wpk_repo + "linux/" + architecture + "/" + wpk_file

    wpk_file_path = os.path.join(UPGRADE_PATH, wpk_file)

    if not os.path.exists(wpk_file_path) and (not valid_sha1_list.get(wpk_file)):
        try:
            result = requests.get(wpk_url)
        except requests.exceptions.RequestException:
            raise Exception("The WPK package could not be obtained")

        if result.ok:
            with open(wpk_file_path, 'wb') as fd:
                for chunk in result.iter_content(chunk_size=128):
                    fd.write(chunk)
        else:
            raise Exception("Can't access to the WPK file in {}".format(wpk_url))

    # Get SHA1 file sum
    if valid_sha1_list.get(wpk_file):
        sha1hash = valid_sha1_list.get(wpk_file)
    else:
        sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
        valid_sha1_list[wpk_file] = sha1hash

    sha_list = []
    for sha in metadata['sha_list']:
        if sha == 'VALIDSHA1':
            sha_list.append(sha1hash)
        else:
            sha_list.append('INVALIDSHA1')

    return sha_list


def test_wpk_manager(set_debug_mode, get_configuration, configure_environment,
                     restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    expected_status = metadata['status']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    log_monitor = FileMonitor(LOG_FILE_PATH)
    expected_error_msg = metadata.get('error_msg')
    sha_list = metadata.get('sha_list')
    injectors = []
    file_name = ''
    installer = ''

    if 'VALIDSHA1' in sha_list:
        sha_list = get_sha_list(metadata)

    command = 'upgrade'
    if metadata.get('command') == 'upgrade_custom':
        command = 'upgrade_custom'
        if not expected_error_msg or ('The WPK file does not exist' not in expected_error_msg):
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
        agent.set_wpk_variables(sha_list[index],
                                metadata['upgrade_exec_result'][index],
                                metadata['upgrade_notification'][index],
                                metadata['upgrade_script_result'][index],
                                stage_disconnect=metadata['stage_disconnect'][index])
        injector = Injector(sender, agent)
        injectors.append(injector)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    agents_id = [int(x.id) for x in agents]

    data = {
        'command': command,
        'parameters': {'agents': agents_id}
    }

    # If have params for test case add to the data to send
    if metadata.get('message_params'):
        data['parameters'].update(metadata.get('message_params'))

    # remove wpk if need check http or version
    if metadata.get('checks') and ('use_http' in metadata.get('checks') or 'version' in metadata.get('checks')):
        remove_wpk_package()

    # Give time for registration key to be available and send a few heartbeats
    time.sleep(40)

    # Send upgrade request
    response = send_message(data, UPGRADE_SOCKET)

    if metadata.get('checks') and (('use_http' in metadata.get('checks')) or ('version' in metadata.get('checks'))):
        # Checking version or http in logs
        try:
            log_monitor.start(timeout=60, callback=wait_download)
        except TimeoutError as err:
            raise AssertionError("Download wpk log took too much!")

        last_log = log_monitor.result()
        if 'use_http' in metadata.get('checks'):
            if metadata.get('message_params') and \
                metadata.get('message_params').get('use_http') and \
                    metadata.get('message_params').get('use_http') == True:
                assert "'http://" in last_log, "Use http protocol did not match expected! Expected 'http://'"
            else:
                assert "'https://" in last_log, "Use http protocol did not match expected! Expected 'https://'"

        if 'version' in metadata.get('checks'):
            if metadata.get('message_params') and \
                    metadata.get('message_params').get('version'):
                assert metadata.get('message_params').get('version') in \
                    last_log, f'Versions did not match expected! Expected {metadata.get("message_params").get("version")}'
            else:
                assert MANAGER_VERSION in last_log, \
                    f'Versions did not match expected! Expected {MANAGER_VERSION}'
        # let time to download wpk
        try:
            log_monitor.start(timeout=600, callback=wait_downloaded)
        except TimeoutError as err:
            raise AssertionError("Finish download wpk log took too much!")
        # time.sleep(60)

    if metadata.get('checks') and ('chunk_size' in metadata.get('checks')):
        # Checking version in logs
        try:
            log_monitor.start(timeout=60, callback=wait_chunk_size)
        except TimeoutError as err:
            raise AssertionError("Chunk size log tooks too much!")
        chunk = metadata.get('chunk_size')
        last_log = log_monitor.result()
        assert f'com write {chunk}' in last_log, \
            f'Chunk size did not match expected! Expected {chunk} obtained {last_log}'

    if metadata.get('checks') and ('wpk_name' in metadata.get('checks')):
        # Checking version in logs
        try:
            log_monitor.start(timeout=120, callback=wait_wpk_custom)
        except TimeoutError as err:
            raise AssertionError("Custom wpk log tooks too much!")

        last_log = log_monitor.result()
        assert f'com upgrade {file_name} {installer}' in last_log, \
            f'Wpk custom package did not match expected! ' \
            f'Expected {metadata.get("message_params").get("file_path")} obtained {last_log}'

    if metadata.get('first_attempt'):
        # Chech that result of first attempt is Success
        assert 'Success' == response['data'][0]['message'], \
            f'First upgrade response did not match expected! ' \
            f'Expected {metadata.get("expected_response")} obtained {response["data"][0]["message"]}'

        repeat_message = data
        # Continue with the validations of first attempt
        task_ids = [item.get('agent') for item in response['data']]
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
            time.sleep(30)
            response = send_message(data, TASK_SOCKET)
            retries = 0
            while (response['data'][0]['status'] != metadata.get('first_attempt')) \
                    and (retries < 10):
                time.sleep(30)
                response = send_message(data, TASK_SOCKET)
                retries += 1
            assert metadata.get('first_attempt') == response['data'][0]['status'], \
                f'First upgrade status did not match expected! ' \
                f'Expected {metadata.get("first_attempt")} obtained {response["data"][0]["status"]}'

        # send upgrade request again
        response = send_message(repeat_message, UPGRADE_SOCKET)

    if metadata.get('expected_response') == 'Success':
        # Chech that result is expected
        assert metadata.get('expected_response') == response['data'][0]['message'], \
            f'Upgrade response did not match expected! ' \
            f'Expected {metadata.get("expected_response")} obtained {response["data"][0]["message"]}'

        # Continue with the test validations
        task_ids = [item.get('agent') for item in response['data']]
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
            time.sleep(30)
            response = send_message(data, TASK_SOCKET)
            retries = 0
            while response['data'][0]['status'] == 'Updating' and retries < 30 and \
                    response['data'][0]['status'] != expected_status[index]:
                time.sleep(30)
                response = send_message(data, TASK_SOCKET)
                retries += 1
            assert expected_status[index] == response['data'][0]['status'], \
                f'Upgrade status did not match expected! ' \
                f'Expected {expected_status[index]} obtained {response["data"][0]["status"]} at index {index}'
            if expected_status[index] == 'Error':
                assert expected_error_msg[index] == response['data'][0]['error_msg'], \
                    f'Error msg did not match expected! ' \
                    f'Expected {expected_error_msg[index]} obtained {response["data"][0]["error_msg"]} at index {index}'
    else:
        assert metadata.get('expected_response') == response['data'][0]['message'], \
            f'Upgrade response did not match expected! ' \
            f'Expected {metadata.get("expected_response")} obtained {response["data"][0]["message"]}'

    for injector in injectors:
        injector.stop_receive()
