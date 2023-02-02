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
worker_host = testinfra_hosts[2]
pytestmark = [pytest.mark.cluster]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'basic_cluster', 'inventory.yml')

host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
add_messages_path = os.path.join(local_path, 'data/synchronization_messages.yml')
delete_messages_path = os.path.join(local_path, 'data/delete_messages.yml')
sync_messages_path = os.path.join(local_path, 'data/synchronization_messages.yml')
script_path = os.path.join(re.sub(r'^.*?wazuh-qa', '/wazuh-qa', local_path), '../utils/get_wdb_agent.py')

tmp_path = os.path.join(local_path, 'tmp')

test_group = 'test_group'
modified_agent = 'wazuh-agent3'
last_agent = 'wazuh-agent2'
while_time = 5
time_to_sync = 21
time_to_agent_reconnect = 180

queries = ['global sql select * from "group" where name="{name}"']


@pytest.fixture(scope='function')
def clean_cluster_logs():
    """Remove old logs from all the existent managers."""
    for host in testinfra_hosts:
        host_manager.clear_file(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
        host_manager.clear_file(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))

        # Its required to restart each node after clearing the log files
        host_manager.get_host(host).ansible('command', 'service wazuh-manager restart', check=False)


def obtain_agent_id(token, agent):
    """Obtain agent's ID.

    Args:
        token (str): the host token.
        agent (str): agent's name.
    """

    response = host_manager.make_api_call(host=master_host, method='GET', token=token,
                                          endpoint=f"/agents?name={agent}")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['data']['total_affected_items'] == 1, 'Failed while trying to obtain the agent\'s ID.'
    agent_id = int(response['json']['data']['affected_items'][0]['id'])

    return agent_id


def check_agent_status(status, token, agent):
    """Restart the removed agent to trigger auto-enrollment.

    Args:
        status (str): the agent status we are looking for.
        token (str): the host token.
        agent (str): agent's name.
    """
    timeout = time() + time_to_agent_reconnect

    while True:
        response = host_manager.make_api_call(host=master_host, method='GET', token=token,
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


def test_agent_groups_create_remove_group(clean_cluster_logs):
    """Check agent agent-groups synchronization works as expected.

    This test will wait for the expected agent-groups messages declared in data/synchronization_messages.yml and
    data/delete_messages.yml. Additionally, it will ensure agent-group synchronization is working by adding a group to
    an agent and removing it afterwards."""

    # Get the token
    master_token = host_manager.get_api_token(master_host)

    # Make sure that the agent is registered and active
    check_agent_status('active', master_token, modified_agent)
    HostMonitor(inventory_path=inventory_path, messages_path=sync_messages_path, tmp_path=tmp_path).run()

    # Create group from master
    response = host_manager.make_api_call(host=master_host, method='POST', token=master_token, endpoint='/groups',
                                          request_body={'group_id': test_group})

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['message'] == f"Group '{test_group}' created."

    # Check if the new information is present in the master and workers dbs
    sleep(time_to_sync)
    for host in testinfra_hosts:
        result = host_manager.run_command(host,
                                          f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                          f"{script_path} '{queries[0].format(name=test_group)}'")
        assert result, f"This db query should have returned something in {host}, but it did not: {result}"
        assert f"'name': '{test_group}'" in result

    # Obtain agent's ID
    agent_id = obtain_agent_id(master_token, modified_agent)
    previous_agent_id = obtain_agent_id(master_token, last_agent)

    # Add group to agent
    response = host_manager.make_api_call(host=master_host, method='PUT', token=master_token,
                                          endpoint=f"/agents/{str(agent_id).zfill(3)}/group/{test_group}")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['message'] == f"All selected agents were assigned to {test_group}"

    # Check if the new information is present in the master and workers dbs
    sleep(time_to_sync)
    queries.append(f'global sync-agent-groups-get {"{"}"condition":"all", "last_id":{previous_agent_id}{"}"}')
    for host in testinfra_hosts:
        result = host_manager.run_command(host,
                                          f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                          f"{script_path} '{queries[1]}'")
        assert result, f"This db query should have returned something in {host}, but it did not: {result}"
        result = json.loads(result[1:-1].replace("'", '"'))
        assert test_group in result['data'][0]['groups']

    # Check whether the addition messages are present.
    HostMonitor(inventory_path=inventory_path, messages_path=add_messages_path, tmp_path=tmp_path).run()

    # Remove group from agent
    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f"/agents/{str(agent_id).zfill(3)}/group/{test_group}")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['message'] == f"Agent '{str(agent_id).zfill(3)}' removed from '{test_group}'."

    # Check if the new information is present in the master and workers dbs
    sleep(time_to_sync)
    for host in testinfra_hosts:
        result = host_manager.run_command(host,
                                          f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                          f"{script_path} '{queries[1]}'")
        assert result, f"This db query should not have returned anything in {host}, but it did: {result}"
        result = json.loads(result[1:-1].replace("'", '"'))
        assert test_group not in result['data'][0]['groups']

    # Remove group
    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f"/groups?groups_list={test_group}")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['message'] == f"All selected groups were deleted"

    # Check if the new information is present in the master and workers dbs
    sleep(time_to_sync)
    for host in testinfra_hosts:
        result = host_manager.run_command(host,
                                          f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                          f"{script_path} '{queries[0].format(name=test_group)}'")
        assert not result, f"This db query should not have returned anything in {host}, but it did: {result}"

    # Check whether the deletion messages are present.
    HostMonitor(inventory_path=inventory_path, messages_path=delete_messages_path, tmp_path=tmp_path).run()
