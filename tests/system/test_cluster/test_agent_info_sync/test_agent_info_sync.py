# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from time import sleep, time

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
testinfra_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
master_host = 'wazuh-master'
pytestmark = [pytest.mark.cluster]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'basic_cluster', 'inventory.yml')

host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
messages_deletion_path = os.path.join(local_path, 'data/messages_deletion.yml')
script_path = os.path.join(re.sub(r'^.*?wazuh-qa', '/wazuh-qa', local_path), '../utils/get_wdb_agent.py')

tmp_path = os.path.join(local_path, 'tmp')
global_db_path = os.path.join(WAZUH_PATH, 'queue', 'db', 'global.db')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')

label = 'test_label'
modified_agent = 'wazuh-agent2'
deleted_agent = 'wazuh-agent3'
while_time = 5
time_to_sync = 21
time_to_agent_reconnect = 180

queries = ['global sql select id from agent where name=\"{agent}\"',
           "global sql select id from labels where key='\\\"{label}\\\"'",
           'global sql select name from agent']


@pytest.fixture(scope='function')
def clean_cluster_logs():
    """Remove old logs from all the existent managers."""
    for host in testinfra_hosts:
        host_manager.clear_file(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
        host_manager.clear_file(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))

        # Its required to restart each node after clearing the log files
        host_manager.get_host(host).ansible('command', 'service wazuh-manager restart', check=False)

    host_manager.clear_file(host='wazuh-agent3', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.get_host('wazuh-agent3').ansible('command', 'service wazuh-agent restart', check=False)


@pytest.fixture(scope='function')
def remove_labels():
    """Remove any label set to the modified wazuh-agent and restart it to apply the new config."""
    yield
    host_manager.add_block_to_file(host=modified_agent, path=f"{WAZUH_PATH}/etc/ossec.conf",
                                   after='</client>', before='<client_buffer>', replace=os.linesep)
    host_manager.get_host(modified_agent).ansible('command', 'service wazuh-agent restart', check=False)


def check_agent_status(status, master_token, agent):
    """Restart the removed agent to trigger auto-enrollment."""
    timeout = time() + time_to_agent_reconnect

    while True:
        response = host_manager.make_api_call(host=master_host, method='GET', token=master_token,
                                              endpoint=f"/agents?name={agent}")
        assert response['status'] == 200, f"Failed when trying obtain agent's information: {response}"

        if int(response['json']['data']['total_affected_items']) == 1:
            if response['json']['data']['affected_items'][0]['status'] == status:
                assert response['json']['data']['affected_items'][0][
                           'name'] == agent, f"The agent's name does not correspond to the deleted one: " \
                                             f"{response['json']['data']['affected_items'][0]['name']}"
                assert response['json']['data']['affected_items'][0]['node_name'] in testinfra_hosts, \
                    f"The agent is reporting to an unknown manager: " \
                    f"{response['json']['data']['affected_items'][0]['node_name']}"
                break
        elif time() > timeout:
            raise TimeoutError(f"The agent '{agent}' is not '{status}' yet.")
        sleep(while_time)
    sleep(time_to_sync)


def test_agent_info_sync(clean_cluster_logs, remove_labels):
    """Check agent agent-info synchronization works as expected.

    This test will wait for the expected agent-info messages declared in data/messages.yml. Additionally, it will
    ensure agent-info synchronization is working by modifying one agent."""

    # Get the token
    master_token = host_manager.get_api_token(master_host)

    # Make sure that the agent is registered and active
    check_agent_status('active', master_token, modified_agent)

    # Add a label to one of the agents and restart it to apply the change
    host_manager.add_block_to_file(host=modified_agent, path=f"{WAZUH_PATH}/etc/ossec.conf",
                                   after='</client>', before='<client_buffer>',
                                   replace=f'<labels><label key="{label}">value</label></labels>')
    host_manager.get_host(modified_agent).ansible('command', 'service wazuh-agent restart', check=False)

    # Obtain the modified agent ID.
    modified_agent_id = host_manager.run_command(master_host,
                                                 f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                                 f"{script_path} '{queries[0].format(agent=modified_agent)}'")

    # Check that the agent label is updated in the master's database.
    sleep(time_to_sync)
    result = host_manager.run_command(master_host,
                                      f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                      f"{script_path} \"{queries[1].format(label=label)}\"")

    assert modified_agent_id, \
        f"The modified agent's ID could not be retrieved. Obtained output: {modified_agent_id}"
    assert result, \
        f"The agent's ID with label {label} could not be retrieved. Obtained output: {result}"
    assert modified_agent_id == result, \
        f"The ID obtained does not correspond to the modified agent's ID"


def test_agent_info_sync_remove_agent(clean_cluster_logs):
    """Check agent agent-info synchronization works as expected when removing an agent from the Master node."""

    # Get the token
    master_token = host_manager.get_api_token(master_host)

    # Make sure that the agent is registered and active
    check_agent_status('active', master_token, deleted_agent)

    # Ensure the agent to be removed is present in the Worker's socket before attempting the test
    agent_list = host_manager.run_command('wazuh-worker2',
                                          f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                          f"{script_path} \"{queries[2]}\"")

    assert deleted_agent in agent_list, f"{deleted_agent} was not found in wazuh-worker2\'s global.db"

    # Obtain the deleted agent ID
    deleted_agent_id = host_manager.run_command(master_host,
                                                f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                                f"{script_path} '{queries[0].format(agent=deleted_agent)}'")
    deleted_agent_id = json.loads(deleted_agent_id.replace('[', '').replace(']', '').replace("'", '"'))

    # Stop the agent to avoid agent auto-enrollment
    host_manager.get_host(deleted_agent).ansible('command', 'service wazuh-agent stop', check=False)

    # Check if the agent is disconnected
    check_agent_status('disconnected', master_token, deleted_agent)

    # Get the ID of the agent
    agent_info = host_manager.run_command(master_host, f"grep {deleted_agent} {client_keys_path}").split(' ')

    assert deleted_agent_id['id'] == int(agent_info[0]) and deleted_agent in agent_info[1], \
        f"{deleted_agent} was not found in Master\'s client.keys file."

    # Remove the agent from Master node
    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f"/agents?agents_list={agent_info[0]}&status=disconnected"
                                                   f"&older_than=0s")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['data']['total_affected_items'] == 1, 'Failed while trying to delete the desired agent.'

    # Check the Workers synchronize and the agent is removed from the nodes
    sleep(time_to_sync)
    for manager in testinfra_hosts:
        assert not host_manager.run_command(manager, f"grep {deleted_agent} {client_keys_path}"), \
            f"{deleted_agent} was found in {manager}\'s client.keys file."

    host_manager.get_host(deleted_agent).ansible('command', 'service wazuh-agent restart', check=False)
    check_agent_status('active', master_token, deleted_agent)

    HostMonitor(inventory_path=inventory_path, messages_path=messages_deletion_path, tmp_path=tmp_path).run()
