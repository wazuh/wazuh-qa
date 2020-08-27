# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import subprocess
import threading
import time

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.agent_simulator import Sender, Injector
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

SERVER_ADDRESS = 'localhost'
MANAGER_VERSION = 'v4.0.0'
WPK_REPOSITORY_4x = 'packages.wazuh.com/4.x/wpk/'
CRYPTO = "aes"
CHUNK_SIZE = 16384

cases = [
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
            'status': 'Updated'
        }
    }
]


params = [ case['params'] for case in cases ]
metadata = [ case['metadata'] for case in cases ]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

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

def test_wpk_manager(get_configuration, configure_environment, restart_service, configure_agents):
    metadata = get_configuration.get('metadata')
    protocol = metadata['protocol']
    expected_status = metadata['status']
    sender = Sender(SERVER_ADDRESS, protocol=protocol)
    for index, agent in enumerate(agents):
        agent.set_wpk_variables(metadata['sha_list'][index], metadata['upgrade_exec_result'][index])

        injector = Injector(sender, agent)
        injector.run()
        if protocol == "tcp":
            sender = Sender(manager_address=SERVER_ADDRESS, protocol=protocol)

    # Give time for registration key to be avilable and send a few heartbeats
    time.sleep(30)

    agents_string = ','.join([x.id for x in agents])
    result = subprocess.run([os.path.join(WAZUH_PATH, "bin", "agent_upgrade"), '-a', agents_string], stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    result_string = result.stdout.decode().split('\n')
    agent_id = None
    upgrade_status = None
    for line in result_string:
        if 'Agent upgrade result' in line:
            words = line.rstrip('.').split(' ')
            agent_id = words[words.index('id:')+1]
            upgrade_status = words[words.index('status:')+1]
            break

    assert expected_status == upgrade_status, f'Upgrade Status did not match expected! Expected {expected_status} obtained {upgrade_status}'


    flag = True
    while flag:
        time.sleep(10)

    return
