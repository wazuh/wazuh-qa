"""
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when an agent pointing to a worker node is registered using enrrolment method and with
       group the change is sync with the cluster.
tier: 0
modules:
    - cluster
components:
    - manager
    - agent
path: /tests/system/test_cluster/test_agent_groups/test_assign_agent_group_with_enrollment.py
daemons:
    - wazuh-db
    - wazuh-clusterd
os_platform:
    - linux
os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
references:
    - https://github.com/wazuh/wazuh-qa/issues/2510
tags:
    - cluster
"""

import os
import time
import pytest

from system import (AGENT_GROUPS_DEFAULT, ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND, restart_cluster,
                    check_keys_file, delete_group_of_agents, check_agent_groups_db)
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools import WAZUH_PATH

# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_agents = ["wazuh-agent1"]
pytestmark = [pytest.mark.cluster, pytest.mark.enrollment_cluster_env]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')

# Variables
timeout = 15
id_group = 'group_test'
path_cluster = '/framework/python/lib/python3.9/site-packages/wazuh-4.4.0-py3.9.egg/wazuh/core/cluster/cluster.json'
enrollment_group = f"""
    <enrollment>
    <groups>{id_group}</groups>
    </enrollment>
                       """


# Tests
@pytest.mark.parametrize("agent_target", ["wazuh-worker1"])
def test_assign_agent_to_a_group(agent_target, clean_environment):
    '''
    description: Check race condition when an agent enrollment process with a group connects to the worker,
                 when worker no receive information about the group and when data of groups is receive,
                 the group is change.
    wazuh_min_version: 4.4.0
    parameters:
        - agent_target:
            type: string
            brief: name of the host where the agent will register
        - clean_enviroment:
            type: fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering the agent key file exists in all nodes.
        - Verify that after registering and before receiving agent group info, it has the 'default' group assigned.
        - Verify that after registering and after receiving agent group info, it has the 'group_test' group assigned.
    expected_output:
        - The agent 'Agent_name' with ID 'Agent_id' belongs to groups: group_test."
    '''
    replace = '\n' + '            "timeout_agent_groups": 40,' '\n' + '            "agent_group_start_delay": 300,\n'

    # Add modify agent_group_start_delay
    host_manager.add_block_to_file(host=test_infra_managers[0], path=f"{WAZUH_PATH}{path_cluster}",
                                   after='"timeout_agent_info": 40,', before='"check_worker_lastkeepalive": 60,',
                                   replace=replace)

    # Create new group
    host_manager.run_command(test_infra_managers[0], f"/var/ossec/bin/agent_groups -q -a -g {id_group}")

    worker_ip = host_manager.run_command(agent_target, f'hostname -i')

    # Modify ossec.conf in agent
    host_manager.add_block_to_file(host=test_infra_agents[0], path=f"{WAZUH_PATH}/etc/ossec.conf",
                                   after="</crypto_method>", before="</client>", replace=enrollment_group)
    host_manager.add_block_to_file(host=test_infra_agents[0], path=f"{WAZUH_PATH}/etc/ossec.conf",
                                   after="<address>", before="</address>", replace=worker_ip)

    restart_cluster([test_infra_managers[0]] + test_infra_agents, host_manager)
    time.sleep(timeout)

    # Check that agent has client key file
    assert check_keys_file(test_infra_agents[0], host_manager), ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND

    try:
        # Chech that the worker has the default group
        query = 'sql select id, `group` from agent;'
        check_agent_groups_db(query, AGENT_GROUPS_DEFAULT, test_infra_managers[1], host_manager)

        replace = '\n' + '            "timeout_agent_groups": 40,' '\n' + '            "agent_group_start_delay": 1,\n'

        # Add modify agent_group_start_delay
        host_manager.add_block_to_file(host=test_infra_managers[0], path=f"{WAZUH_PATH}{path_cluster}",
                                       after='"timeout_agent_info": 40,', before='"check_worker_lastkeepalive": 60,',
                                       replace=replace)

        restart_cluster([test_infra_managers[0]], host_manager)
        time.sleep(timeout)
        # Check that agent has group set to default and then override group info
        check_agent_groups_db(query, id_group, test_infra_managers[1], host_manager)

    finally:
        # Delete group of agent
        delete_group_of_agents(test_infra_managers[0], id_group, host_manager)
