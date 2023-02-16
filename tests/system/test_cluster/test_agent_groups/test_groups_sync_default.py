'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: These tests check that when a cluster has a series of agents registered and connecting one after the other,
       and it is unable to do a Sync, that after a expected time, a Sync is forced and the DB is Synched.
tier: 2
modules:
    - cluster
components:
    - manager
    - agent
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
    - https://github.com/wazuh/wazuh-qa/issues/2514
tags:
    - wazuh-db
'''
import os
import time

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.system import HostManager
from system import check_agent_groups
from system.test_cluster.test_agent_groups.common import register_agent


# Hosts
test_infra_managers = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
pytestmark = [pytest.mark.cluster, pytest.mark.big_cluster_env]
agents_in_cluster = 40
test_infra_agents = []
for x in range(agents_in_cluster):
    test_infra_agents.append("wazuh-agent" + str(x+1))

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'big_cluster_40_agents', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
test_time = 800
sync_delay = 40


# Tests
@pytest.mark.parametrize("agent_host", test_infra_managers[0:2])
def test_agent_groups_sync_default(agent_host, clean_environment):
    '''
    description: Check that after a long time when the manager has been unable to synchronize de databases, because
    new agents are being continually added, database synchronization is forced and the expected information is in
    all nodes after the expected sync time. For this, an agent is restarted and connects to the agent every roughly 10
    seconds, during 400 seconds. After all agents have been registered, it is checked that the wazuhDB has been synched
    in all the cluster nodes.
    wazuh_min_version: 4.4.0
    parameters:
        - agent_host:
            type: List
            brief: Name of the host where the agent will register in each case.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
    assertions:
        - Verify that after registering and after starting the agent, the agent has the default group is assigned.
        - Assert that all Agents have been restarted
    expected_output:
        - The 'Agent_name' with ID 'Agent_id' belongs to groups: 'group_name'.
    '''

    # Register agents in manager
    agent_data = []
    for index, agent in enumerate(test_infra_agents):
        data = register_agent(agent, agent_host, host_manager)
        agent_data.append(data)

    # get the time before all the process is started
    end_time = time.time() + test_time
    active_agent = 0
    while time.time() < end_time:
        if active_agent < agents_in_cluster:
            host_manager.run_command(test_infra_agents[active_agent], f'{WAZUH_PATH}/bin/wazuh-control start')
            active_agent = active_agent + 1

    assert active_agent == agents_in_cluster, f"Unable to restart all agents in the expected time. \
                                                Agents restarted: {active_agent}"

    time.sleep(sync_delay)

    # Check that agent has the expected group assigned in all nodes
    for agent in agent_data:
        check_agent_groups(agent[1], "default", test_infra_managers, host_manager)
