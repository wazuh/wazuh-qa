import os
import pytest
from time import sleep

from system import (ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND, check_agent_groups, check_keys_file,
                    create_new_agent_group, assign_agent_to_new_group, restart_cluster, execute_wdb_query, get_group_id,
                    delete_agent_group)
from wazuh_testing import T_10
from system.test_cluster.test_agent_groups.common import register_agent
from wazuh_testing.tools.configuration import get_test_cases_data
from wazuh_testing.tools.system_monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

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
messages_path = os.path.join(data_path, 'remove_group_messages.yaml')

# Variables
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
queries = ['sql select `group` from agent;', 'sql select name from `group`;', 'sql select id_group from belongs;']
TIMEOUT_GET_GROUPS_ID = 3

# Fixtures
@pytest.fixture()
def pre_configured_groups(target_node, group):
    """Fixture to create a group and assign an agent during the setup.
    Args:
        target_node (str): Name of the host where the agent will register.
        group (str): Group name.
    """
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

    yield

    if group != 'default':
        delete_agent_group(test_infra_managers[0], group, host_manager)


# Tests
@pytest.mark.parametrize('metadata', t1_configuration_metadata, ids=t1_case_ids)
@pytest.mark.parametrize('group', ['group_test'])
@pytest.mark.parametrize('target_node', ['wazuh-master', 'wazuh-worker1'])
def test_remove_group(metadata, group, target_node, pre_configured_groups, clean_environment):
    '''
    description: Check that a group is completely deleted from all nodes when using different deletion methods, with the
                 exception of cases where the group folder is deleted on a worker node.
    wazuh_min_version: 4.4.0
    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - group:
            type: string
            brief: Group name.
        - target_node:
            type: string
            brief: Name of the host where the agent will register.
        - pre_configured_groups:
            type: fixture
            brief: Create group, register and assign agent during the setup.
        - clean_environment:
            type: fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify [Agent-groups send full] task finished when the group folder is removed in a worker node.
        - Verify group name is present in agent table when the group folder is removed in a worker node.
        - Verify group id is present in agent table when the group folder is removed in a worker node.
        - Verify group name is not present in agent table when group is deleted.
        - Verify group id is not present in agent table when group is deleted.
    '''
    # Get group IDs
    group_ids = {}
    for manager in test_infra_managers:
        group_ids[manager] = str(get_group_id(group, manager, host_manager))

    # Delete group
    exec(metadata['method'])
    sleep(T_10)

    if not metadata['deleted']:
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path,
                    tmp_path=tmp_path).run(update_position=True)

        sleep(TIMEOUT_GET_GROUPS_ID)

        for manager in test_infra_managers:
            group_ids[manager] = str(get_group_id(group, manager, host_manager))

    # Check group is deleted or not if expected in agent table in every node
    for query in queries:
        for manager in test_infra_managers:
            global_query = f"global '{query}'"
            response = execute_wdb_query(global_query, manager, host_manager)
            if metadata['deleted']:
                if 'id_group' in query:
                    assert group_ids[manager] not in response, f"Group not deleted correctly in {manager}"
                else:
                    assert group not in response, f"Group not deleted correctly in {manager}"
            else:
                if 'id_group' in query:
                    assert group_ids[manager] in response, f"Group deleted in {manager}"
                else:
                    assert group in response, f"Group deleted in {manager}"
