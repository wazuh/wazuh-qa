import hashlib
import json
import os
import time
import pytest

import wazuh_testing as fw
from system.test_cluster.test_agent_groups.common import register_agent
from system import (create_new_agent_group, delete_agent_group, assign_agent_to_new_group, restart_cluster,
                    execute_wdb_query, remove_cluster_agents, unassign_agent_from_group)
from wazuh_testing.tools.system import HostManager


pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_agents = ["wazuh-agent1", "wazuh-agent2"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))

# Global hash query
command = 'sync-agent-groups-get {"condition": "sync_status", "set_synced": false, "get_global_hash": true}'
query = f"global '{command}'"


# Functions
def calculate_global_hash(host, host_manager):
    """Calculate the global hash.
    Args:
        host (str): a host on which to calculate the global hash
        host_manager (object): a host manager object with not None inventory_path
    Returns:
        global hash (str): global hash obtained
    """
    GET_GROUP_HASH = '''global "sql SELECT group_hash FROM agent WHERE
                     id > 0 AND group_hash IS NOT NULL ORDER BY id
                     LIMIT {limit} OFFSET {offset}"'''

    limit = 1000
    offset = 0
    group_hashes = []

    while True:
        result = execute_wdb_query(GET_GROUP_HASH.format(limit=1000, offset=offset), host, host_manager)
        if result == '[]':
            break
        offset += limit
        group_hashes.extend([item['group_hash'] for item in json.loads(result)])

    if not group_hashes:
        return None

    return hashlib.sha1("".join(group_hashes).encode()).hexdigest()


# Fixtures
@pytest.fixture()
def configure_groups(group):
    """Fixture to create a group during the setup and delete it during the tear down."""
    # Create group
    if group != 'default':
        create_new_agent_group(test_infra_managers[0], group, host_manager)

    yield

    # Delete group
    if group != 'default':
        delete_agent_group(test_infra_managers[0], group, host_manager)


# Tests
@pytest.mark.parametrize('n_agents', [1, 2])
@pytest.mark.parametrize('group', ['default', 'multigroup1'])
@pytest.mark.parametrize('target_node', ['wazuh-master', 'wazuh-worker1'])
def test_group_hash(target_node, group, n_agents, configure_groups, clean_environment):
    '''
    description: Check that when an agent registered in the manager and assigned to a group, the global hash is the
                 the expected one.
    wazuh_min_version: 4.4.0
    parameters:
        - target_node:
            type: String
            brief: Name of the host where the agent will register.
        - group
            type: String
            brief: Determine if the group to assign.
        - configure_groups:
            type: Fixture
            brief: Create and delete groups.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that there is a global hash.
        - Verify that the global hash is the same in every node.
    '''
    # Register agent with agent-auth
    agents_data = []
    for agent in range(n_agents):
        agent_data = register_agent(test_infra_agents[agent], target_node, host_manager)
        agents_data.append(agent_data)

    # Restart agent
    restart_cluster(test_infra_agents, host_manager)
    time.sleep(fw.T_20)

    # Assing group for multigroups case
    for agent in range(n_agents):
        if group != 'default':
            assign_agent_to_new_group(test_infra_managers[0], group, agents_data[agent][1], host_manager)
    time.sleep(fw.T_20)

    # Calculate global hash
    expected_global_hash = calculate_global_hash(test_infra_managers[0], host_manager)
    assert expected_global_hash is not None, 'No group assigned'

    for node in test_infra_managers:
        # Get global hash
        obtained_global_hash = json.loads(execute_wdb_query(query, node, host_manager))[0]['hash']

        assert expected_global_hash == obtained_global_hash, f"{node} reported different global group hash"

    if group != 'default':
        # Unassign one agent from group

        unassign_agent_from_group(test_infra_managers[0], group, agents_data[0][1], host_manager)
        time.sleep(fw.T_20)

        # Calculate global hash
        expected_global_hash = calculate_global_hash(test_infra_managers[0], host_manager)
        assert expected_global_hash is not None, 'No group assigned'

        for node in test_infra_managers:
            # Get global hash
            obtained_global_hash = json.loads(execute_wdb_query(query, node, host_manager))[0]['hash']
            assert expected_global_hash == obtained_global_hash, f"{node} reported different global group hash"

    if n_agents >= 2:
        # Delete one agent
        remove_cluster_agents(test_infra_managers[0], [test_infra_agents[0]], host_manager, [agents_data[0][1]])
        time.sleep(fw.T_20)

        # Calculate global hash
        expected_global_hash = calculate_global_hash(test_infra_managers[0], host_manager)
        assert expected_global_hash is not None, 'No group assigned'

        for node in test_infra_managers:
            # Get global hash
            obtained_global_hash = json.loads(execute_wdb_query(query, node, host_manager))[0]['hash']
            assert expected_global_hash == obtained_global_hash, f"{node} reported different global group hash"
