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
test_infra_managers = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
test_infra_agents = ["wazuh-agent1"]
master_host = 'wazuh-master'
worker_host = test_infra_managers[1]
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
queries = ['sql select * from "group" where name="test_group"']


# Tests
def test_agent_groups_create_remove_group(clean_environment):
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
    for host in test_infra_managers:
        created_group = execute_wdb_query(f"global '{queries[0]}'", host, host_manager)
        assert f'"name": "{test_group}"' in created_group

    # Add group to agent
    response = host_manager.make_api_call(host=master_host, method='PUT', token=master_token,
                                          endpoint=f"/agents/{agent_id}/group/{test_group}")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['message'] == f"All selected agents were assigned to {test_group}"

    # Check if the new information is present in the master and workers dbs
    sleep(time_to_sync)
    queries.append(f'sync-agent-groups-get {"{"}"condition":"all", "id":{agent_id}{"}"}')
    for host in test_infra_managers:
        assigned_groups = execute_wdb_query(f"global '{queries[1]}'", host, host_manager)
        assert test_group in assigned_groups

    # Check whether the addition messages are present.
    HostMonitor(inventory_path=inventory_path, messages_path=add_messages_path, tmp_path=tmp_path).run()

    # Remove group from agent
    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f"/agents/{agent_id}/group/{test_group}")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['message'] == f"Agent '{agent_id}' removed from '{test_group}'."

    # Check if the new information is present in the master and workers dbs
    sleep(time_to_sync)
    for host in test_infra_managers:
        assigned_groups = execute_wdb_query(f"global '{queries[1]}'", host, host_manager)
        assert test_group not in assigned_groups

    # Remove group
    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f"/groups?groups_list={test_group}")

    assert response['status'] == 200, f"API failure: {response}"
    assert response['json']['message'] == 'All selected groups were deleted'

    # Check if the new information is present in the master and workers dbs
    sleep(time_to_sync)
    for host in test_infra_managers:
        created_group = execute_wdb_query(f"global '{queries[0]}'", host, host_manager)
        print(created_group)
        assert created_group == '[]'

    # Check whether the deletion messages are present.
    HostMonitor(inventory_path=inventory_path, messages_path=delete_messages_path, tmp_path=tmp_path).run()
