'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system

'''

import os
from time import sleep

import pytest

from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
testinfra_hosts = ["wazuh-manager", "wazuh-agent1"]
wazuh_agent_processes = ['wazuh-agentd', 'wazuh-modulesd', 'wazuh-execd', 'wazuh-syscheckd', 'wazuh-logcollector']

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'basic_environment', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
messages_before_agent_stop_path = os.path.join(local_path, 'data/messages_before_agent_stop_path.yml')
tmp_path = os.path.join(local_path, 'tmp')

wait_agent_start = 70


# Remove the agent once the test has finished
@pytest.fixture(scope='function')
def clean_environment():
    yield
    agent_id = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    host_manager.get_host('wazuh-manager').ansible("command", f'{WAZUH_PATH}/bin/manage_agents -r {agent_id}',
                                                   check=False)
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="stopped")
    host_manager.control_service(host='wazuh-manager', service='wazuh', state="started")
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))


def test_stop_agent(clean_environment):
    '''

    '''
    # Clean ossec.log and cluster.log
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="started")
    sleep(wait_agent_start)
    host_manager.run_command(host='wazuh-manager', cmd='service wazuh-manager stop')

    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_before_agent_stop_path,
                tmp_path=tmp_path).run()
    host_manager.run_command(host='wazuh-agent1', cmd='service wazuh-agent stop')

    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run()

    for process in wazuh_agent_processes:
        try:
            pid = host_manager.get_running_process(host='wazuh-agent1', process = process)
        except:
            pass
        else:
            pytest.fail(f'{process} was running')
