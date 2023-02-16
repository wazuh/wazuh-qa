# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
from time import sleep

import pytest
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager
from system.test_cluster.test_agent_groups.common import register_agent
from system import AGENT_STATUS_ACTIVE, check_agent_status, restart_cluster, execute_wdb_query

# Hosts
test_infra_managers = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
test_infra_agents = ["wazuh-agent1"]
master_host = 'wazuh-master'
worker_host = test_infra_managers[1]
pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')

host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
add_messages_path = os.path.join(local_path, 'data/add_messages.yml')
delete_messages_path = os.path.join(local_path, 'data/delete_messages.yml')
sync_messages_path = os.path.join(local_path, 'data/synchronization_messages.yml')
script_path = os.path.join(re.sub(r'^.*?wazuh-qa', '/wazuh-qa', local_path), '../utils/get_wdb_agent.py')
tmp_path = os.path.join(local_path, 'tmp')

# Variables
test_group = 'test_group'
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

    # Register agent
    agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], worker_host, host_manager)
    restart_cluster(test_infra_agents, host_manager)

    # Check that the agent is active
    sleep(time_to_sync)
    check_agent_status(agent_id, agent_name, agent_ip, AGENT_STATUS_ACTIVE, host_manager, test_infra_managers)

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
        assert created_group == '[]'

    # Check whether the deletion messages are present.
    HostMonitor(inventory_path=inventory_path, messages_path=delete_messages_path, tmp_path=tmp_path).run()
