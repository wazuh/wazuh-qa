# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-worker1", "wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'basic_cluster', 'inventory.yml')

host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')

label = "test_label"


@pytest.fixture(scope='module')
def configure_environment():
    host_manager.get_host('wazuh-master').ansible('command', f'service wazuh-manager stop', check=False)
    host_manager.get_host('wazuh-worker1').ansible('command', f'service wazuh-manager stop', check=False)
    host_manager.get_host('wazuh-worker2').ansible('command', f'service wazuh-manager stop', check=False)
    host_manager.get_host('wazuh-agent1').ansible('command', f'service wazuh-agent stop', check=False)
    host_manager.get_host('wazuh-agent2').ansible('command', f'service wazuh-agent stop', check=False)
    host_manager.get_host('wazuh-agent3').ansible('command', f'service wazuh-agent stop', check=False)
    host_manager.clear_file(host='wazuh-master',  file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    host_manager.clear_file(host='wazuh-worker1', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    host_manager.clear_file(host='wazuh-worker2', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    yield
    # Remove the label configuration
    host_manager.add_block_to_file(host='wazuh-agent2', path=f'{WAZUH_PATH}/etc/ossec.conf', after='</client>',
                                   before='<client_buffer>', replace='')
    # Restart agent 2 to apply label removal.
    host_manager.get_host('wazuh-agent2').ansible('command', f'service wazuh-agent restart', check=False)

    # Restart the removed agent to re-register in the worker to avoid impact over following tests
    host_manager.get_host('wazuh-agent3').ansible('command', f'service wazuh-agent restart', check=False)


def test_agent_info_sync(configure_environment):
    """Check agent agent-info synchronization works as expected.

    This test will wait for the expected agent-info messages declared in data/messages.yml. Additionally, it will
    ensure agent-info synchronization is working by modifying one agent and removing another one."""
    host_manager.control_service(host='wazuh-master', service='wazuh', state="started")
    host_manager.control_service(host='wazuh-worker1', service='wazuh', state="started")
    host_manager.control_service(host='wazuh-worker2', service='wazuh', state="started")

    # Add a label to one of the agents
    host_manager.add_block_to_file(host='wazuh-agent2', path=f'{WAZUH_PATH}/etc/ossec.conf', after='</client>',
                                   before='<client_buffer>',
                                   replace=f'<labels><label key="{label}">value</label></labels>')

    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="started")
    host_manager.control_service(host='wazuh-agent2', service='wazuh', state="started")
    host_manager.control_service(host='wazuh-agent3', service='wazuh', state="started")

    # Run the callback checks for the cluster.log
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()

    # Check the wazuh-agent2's label is present in the Master node DB
    master_label = host_manager.run_command('wazuh-master', f'sqlite3 {WAZUH_PATH}/queue/db/global.db '
                                                            f'"SELECT key FROM labels LIMIT 1;"')
    assert master_label == f'"{label}"'

    # Check the agent2 is present on the Worker2's client.keys
    agent_id = host_manager.run_command('wazuh-worker1', f'grep wazuh-agent2 {WAZUH_PATH}/etc/client.keys')
    assert agent_id, f'wazuh-agent2 was not found in wazuh-worker2\'s client.keys file.'

    # Stop agent2 to avoid agent enrollment
    host_manager.get_host('wazuh-agent2').ansible('command', f'service wazuh-agent stop', check=False)

    # Remove an agent
    agent_id = host_manager.run_command('wazuh-master', f'grep wazuh-agent2 {WAZUH_PATH}/etc/client.keys')
    assert agent_id, f'wazuh-agent2 was not found in Master\'s client.keys file.'
    host_manager.run_command('wazuh-master', f'{WAZUH_PATH}/bin/manage_agents -r {agent_id[0:3]}')

    # Run again the callback checks for the cluster.log to ensure the info is synchronized
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()

    # Check the removed agent is not present in wazuh-worker1's client.keys
    agent_id = host_manager.run_command('wazuh-worker1', f'grep wazuh-agent2 {WAZUH_PATH}/etc/client.keys')
    assert agent_id is ""
