import os
import pytest

from system.test_cluster.test_agent_groups.common import register_agent
from system import (ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND, check_agent_groups, check_keys_file,
                    create_new_agent_group, assign_agent_to_new_group, restart_cluster, execute_wdb_query, get_group_id)
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.configuration import get_test_cases_data

pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

# Hosts
test_infra_managers = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
test_infra_agents = ['wazuh-agent1', 'wazuh-agent2']

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')
t1_cases_path = os.path.join(data_path, 'cases_remove_group.yaml')

# Variables
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
queries = ['sql select `group` from agent;', 'sql select name from `group`;', 'sql select id_group from belongs;']


# Fixtures
@pytest.fixture()
def pre_configured_groups(target_node, group):
    """Fixture to create a group and assign an agent during the setup."""
    # Create group
    if group != 'default':
        create_new_agent_group(test_infra_managers[0], group, host_manager)

    # Register agent with agent-auth
    agent_ip, agent_id, agent_name, manager_ip = register_agent(test_infra_agents[0], target_node,
                                                                host_manager)

    # Restart agent
    restart_cluster([test_infra_agents[0]], host_manager)

    # Check that agent has client key file
    assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

    # Assign agent to group
    if group != 'default':
        assign_agent_to_new_group(test_infra_managers[0], group, agent_id, host_manager)

    # Check that agent has group assigned on every node
    check_agent_groups(agent_id, group, test_infra_managers, host_manager)


# Tests
@pytest.mark.parametrize('metadata', t1_configuration_metadata, ids=t1_case_ids)
@pytest.mark.parametrize('group', ['group_test'])
@pytest.mark.parametrize('target_node', ['wazuh-master'])
def test_remove_group(metadata, group, target_node, pre_configured_groups, clean_environment):
    '''
    description:
    wazuh_min_version: 4.4.0
    parameters:
    assertions:
    '''
    # Get group ID
    group_id = get_group_id(group, test_infra_managers[0], host_manager)

    # Delete group
    exec(metadata['method'])

    # Check group is deleted in agent table in every node
    for query in queries:
        for manager in test_infra_managers:
            global_query = f"global '{query}'"
            response = execute_wdb_query(global_query, manager, host_manager)
            print(manager)
            assert group and str(group_id) not in response, 'Group not deleted correctly'
