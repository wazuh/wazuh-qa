
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
path: /tests/system/test_cluster/test_agent_groups/test_assign_agent_to_a_group_api.py
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
    - https://github.com/wazuh/wazuh-qa/issues/2506
tags:
    - cluster
"""

import os

import pytest
from wazuh_testing.tools.system import HostManager
from system import (check_agent_groups, restart_cluster, clean_cluster_logs,
                    check_keys_file, remove_cluster_agents, delete_group_of_agents, get_id_from_agent)
from wazuh_testing.tools import WAZUH_PATH


# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
test_infra_agents = ["wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
tmp_path = os.path.join(local_path, 'tmp')
id_group = 'group_test'
enrollment_group = """ 
    <enrollment>
    <groups>group_test</groups>
    </enrollment>
                       """

@pytest.fixture(scope='function')
def clean_environment():

    clean_cluster_logs(test_infra_agents + test_infra_managers, host_manager)

    yield
    # Remove the agent once the test has finished
    remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)


@pytest.mark.parametrize("agent_target", ["wazuh-worker1"])
def test_assign_agent_to_a_group(agent_target, clean_environment):
    '''
    description: Check agent enrollment process and new group assignment works as expected in a cluster environment.
                 Check that when an agent pointing to a master/worker node is registered, and when
                 it's assigned to a new group using API the change is sync with the cluster.
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

    # Add modify file wazuh/framework/wazuh/core/cluster/cluster.json - "sync_agent_groups" 

    # Create new group
    host_manager.run_command(test_infra_managers[0], f"/var/ossec/bin/agent_groups -q -a -g {id_group}")

    worker_ip = host_manager.run_command(agent_target, f'hostname -i')
    
    # Modify ossec.conf
    host_manager.add_block_to_file(host=test_infra_agents[0], path=f"{WAZUH_PATH}/etc/ossec.conf",
                                   after="</crypto_method>", before="</client>", replace=enrollment_group)
    host_manager.add_block_to_file(host=test_infra_agents[0], path=f"{WAZUH_PATH}/etc/ossec.conf",
                                   after="<address>", before="</address>", replace=worker_ip)
                     
    restart_cluster(test_infra_agents, host_manager)
    agent_id = get_id_from_agent(test_infra_agents[0], host_manager)

    # Check that agent has client key file
    assert check_keys_file(test_infra_agents[0], host_manager)

    try:
        check_agent_groups(agent_id, 'default', test_infra_managers, host_manager)

        # Check that agent has group set to dafault and then override group info
        check_agent_groups(agent_id, id_group, test_infra_managers, host_manager)
    

    finally:
        # Delete group of agent
        delete_group_of_agents('wazuh-master', id_group, host_manager)
