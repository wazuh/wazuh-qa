'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: sys
tier: 0
modules:
    - enrollment
components:
    - manager
    - agent
daemons:
    - wazuh-authd
    - wazuh-agentd
os_platform:
    - linux
os_version:
    - Debian Buster
references:
    - https://documentation.wazuh.com/current/user-manual/registering/agent-enrollment.html
'''

import os
import pytest
import re
import threading
import time

from system import restart_cluster
from system.test_cluster.test_agent_groups.common import register_agent
from wazuh_testing import T_10, T_30
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.system_monitoring import HostMonitor


inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'big_cluster_40_agents', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..',
                               'provisioning', 'big_cluster_40_agents', 'roles', 'agent-role', 'files', 'ossec.conf')
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')

test_infra_managers = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
workers = ['wazuh-worker1', 'wazuh-worker2']
test_infra_agents = []

number_agents = 40
for number_agent in range(number_agents):
    test_infra_agents.append(f'wazuh-agent{number_agent+1}')

pytestmark = [pytest.mark.cluster, pytest.mark.big_cluster_40_agents_env]


@pytest.fixture()
def configure_environment():
    for agent in test_infra_agents:
        register_agent(agent, test_infra_managers[0], host_manager)
    restart_cluster(test_infra_agents, host_manager, parallel=True)
    time.sleep(T_30)
    connection_summary = host_manager.get_agents_summary_status(test_infra_managers[0])['data']['connection']
    assert connection_summary['active'] == connection_summary['total'] == number_agents, 'Not all agents are active yet'
    host_manager.clear_file(host=test_infra_managers[0], file_path=LOG_FILE_PATH)

    yield

    restart_cluster(test_infra_managers + test_infra_agents, host_manager, parallel=True)


@pytest.fixture()
def stop_gracefully_all_agents():
    threads = []
    for agent in test_infra_agents:
        thread = threading.Thread(target=host_manager.run_command, args=(agent, f'{WAZUH_PATH}/bin/wazuh-control stop'))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


def test_shut_down_message_gracefully_stopped_agent(configure_environment, stop_gracefully_all_agents):
    '''
        description: Checking shutdown message when socket is closed.
        wazuh_min_version: 4.6.0
        parameters:
            - configure_environment:
                type: function
                brief: Register and restart all the agents to manipulate them after.
            - stop_gracefully_all_agents:
                type: function
                brief: Stop agents gracefully
        assertions:
            - Verify that all agents status became 'Disconnected' after gracefully shutdown.

        input_description: Different use cases are found in the test module and include parameters.

        expected_output:
            - Gracefully closed, it is expected to find agents 'Disconected' in agent-manager
    '''
    time.sleep(T_10)
    shutdown_messages = 0

    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()
    ossec_log = host_manager.get_file_content(test_infra_managers[0], LOG_FILE_PATH)
    for line in ossec_log.split('\n'):
        if 'HC_SHUTDOWN' in line:
            shutdown_messages += 1
    matches = re.findall(r"Disconnected", host_manager.run_command(test_infra_managers[0],
                                                                   f'{WAZUH_PATH}/bin/agent_control -l'))
    assert len(matches) == number_agents == shutdown_messages
