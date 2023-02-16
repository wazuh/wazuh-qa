# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-worker1", "wazuh-agent1"]
pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')


# Remove the agent once the test has finished
@pytest.fixture(scope='module')
def clean_environment():
    yield
    agent_id = host_manager.run_command('wazuh-master', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    host_manager.get_host('wazuh-master').ansible("command", f'{WAZUH_PATH}/bin/manage_agents -r {agent_id}',
                                                  check=False)
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="stopped")
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))


def test_agent_enrollment(clean_environment):
    """Check agent enrollment process works as expected. An agent pointing to a worker should be able to register itself
    into the master by starting Wazuh-agent process."""
    # Clean ossec.log and cluster.log
    host_manager.clear_file(host='wazuh-master', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-worker1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-master', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    host_manager.clear_file(host='wazuh-worker1', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))

    # Start the agent enrollment process by restarting the wazuh-agent
    host_manager.control_service(host='wazuh-master', service='wazuh', state="restarted")
    host_manager.control_service(host='wazuh-worker1', service='wazuh', state="restarted")
    host_manager.get_host('wazuh-agent1').ansible('command', f'service wazuh-agent restart', check=False)

    # Run the callback checks for the ossec.log and the cluster.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run()

    # Make sure the worker's client.keys is not empty
    assert host_manager.get_file_content('wazuh-worker1', os.path.join(WAZUH_PATH, 'etc', 'client.keys'))

    # Make sure the agent's client.keys is not empty
    assert host_manager.get_file_content('wazuh-agent1', os.path.join(WAZUH_PATH, 'etc', 'client.keys'))

    # Check if the agent is active
    agent_id = host_manager.run_command('wazuh-master', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    assert host_manager.run_command('wazuh-master', f'{WAZUH_PATH}/bin/agent_control -i {agent_id} | grep Active')
