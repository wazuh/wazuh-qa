# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-worker1", "wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'basic_cluster', 'inventory.yml')

host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
messages_path_remove = os.path.join(local_path, 'data/messages_remove_agent.yml')
tmp_path = os.path.join(local_path, 'tmp')
global_db_path = os.path.join(WAZUH_PATH, "queue", "db", "global.db")
client_keys_path = os.path.join(WAZUH_PATH, "etc", "client.keys")

label = "test_label"
modified_agent = "wazuh-agent2"
deleted_agent = "wazuh-agent3"


@pytest.fixture(scope='function')
def clean_cluster_logs():
    host_manager.clear_file(host='wazuh-master', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    host_manager.clear_file(host='wazuh-worker1', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    host_manager.clear_file(host='wazuh-worker2', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    # Its required to restart each node after clearing the log files
    host_manager.get_host('wazuh-master').ansible('command', f'service wazuh-manager restart', check=False)
    host_manager.get_host('wazuh-worker1').ansible('command', f'service wazuh-manager restart', check=False)
    host_manager.get_host('wazuh-worker2').ansible('command', f'service wazuh-manager restart', check=False)


@pytest.fixture(scope='function')
def remove_labels():
    """Remove any label set to the modified wazuh-agent and restart it to apply the new config."""
    yield
    host_manager.add_block_to_file(host=modified_agent, path=f'{WAZUH_PATH}/etc/ossec.conf',
                                   after='</client>', before='<client_buffer>', replace=os.linesep)
    host_manager.get_host(modified_agent).ansible('command', f'service wazuh-agent restart', check=False)


@pytest.fixture(scope='function')
def register_agent():
    """Restart the removed agent to trigger auto-enrollment."""
    yield
    host_manager.get_host(deleted_agent).ansible('command', f'service wazuh-agent restart', check=False)


def test_agent_info_sync(clean_cluster_logs, remove_labels):
    """Check agent agent-info synchronization works as expected.

    This test will wait for the expected agent-info messages declared in data/messages.yml. Additionally, it will
    ensure agent-info synchronization is working by modifying one agent."""

    # Add a label to one of the agents and restart it to apply the change
    host_manager.add_block_to_file(host=modified_agent, path=f'{WAZUH_PATH}/etc/ossec.conf',
                                   after='</client>', before='<client_buffer>',
                                   replace=f'<labels><label key="{label}">value</label></labels>')
    host_manager.get_host(modified_agent).ansible('command', f'service wazuh-agent restart', check=False)

    # Run the callback checks for the Master and Worker nodes
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()


def test_agent_info_sync_remove_agent(clean_cluster_logs, register_agent):
    """Check agent agent-info synchronization works as expected when removing an agent from the Master node."""

    # Ensure the agent to be removed is present in the Worker's global.db before attempting the test
    agent_list = host_manager.run_command('wazuh-worker2', f'sqlite3 {global_db_path} "SELECT name FROM agent;"')
    assert deleted_agent in agent_list, f'{deleted_agent} was NOT found in wazuh-worker2\'s global.db'

    # Stop the agent to avoid agent auto-enrollment
    host_manager.get_host(deleted_agent).ansible('command', f'service wazuh-agent stop', check=False)

    # Get the ID of the agent
    agent_id = host_manager.run_command('wazuh-master', f'grep {deleted_agent} {client_keys_path}')
    assert agent_id and agent_id != "", f'{deleted_agent} was not found in Master\'s client.keys file.'

    # Remove the agent from Master node
    host_manager.run_command('wazuh-master', f'{WAZUH_PATH}/bin/manage_agents -r {agent_id[0:3]}')

    # Check the Workers synchronize and the agent is removed from the nodes
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path_remove, tmp_path=tmp_path).run()
