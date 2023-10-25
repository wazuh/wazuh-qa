# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
from os.path import join, dirname, abspath
from time import sleep

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager
from system.test_cluster.test_agent_groups.common import register_agent
from system import restart_cluster, check_agent_status, AGENT_STATUS_ACTIVE


pytestmark = [pytest.mark.cluster, pytest.mark.basic_cluster_env]

test_infra_agents = ['wazuh-agent3']
test_infra_managers = ['wazuh-master', 'wazuh-worker2']
master_host = 'wazuh-master'
worker_host = 'wazuh-worker2'
agent_host = 'wazuh-agent3'
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
script_path = os.path.join(re.sub(r'^.*?wazuh-qa', '/wazuh-qa', local_path), '../utils/get_wdb_agent.py')

tmp_path = os.path.join(local_path, 'tmp')
inventory_path = join(dirname(dirname(dirname(abspath(__file__)))), 'provisioning', 'basic_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
while_time = 5
time_to_sync = 20
time_to_agent_reconnect = 180

# Each file should exist in all hosts specified in 'hosts'.
files = [{'path': join(WAZUH_PATH, 'queue', 'rids', '{id}'), 'hosts': test_infra_managers},
         {'path': join(WAZUH_PATH, 'queue', 'diff', '{name}'), 'hosts': [worker_host]},
         {'path': join(WAZUH_PATH, 'queue', 'db', '{id}.db'), 'hosts': [worker_host]}]

queries = ['global sql select * from agent where id={id}',
           'global sql select * from belongs where id_agent={id}']


def test_agent_files_deletion(clean_environment):
    """Check that when an agent is deleted, all its related files in managers are also removed."""
    agent_data = register_agent(agent_host, worker_host, host_manager)
    agent_id = agent_data[1]
    agent_name = agent_data[2]

    restart_cluster(test_infra_agents+test_infra_managers, host_manager)
    sleep(time_to_sync)

    # Check if the agent is connected
    check_agent_status(agent_id, agent_name, agent_data[0], AGENT_STATUS_ACTIVE,
                       host_manager, test_infra_managers)

    # Get the token
    master_token = host_manager.get_api_token(master_host)
    # Get the current ID and name of the agent that is reporting to worker_host.
    response = host_manager.make_api_call(host=master_host, method='GET', token=master_token,
                                          endpoint=f"/agents?select=id,name&q=manager={worker_host}")

    assert response['status'] == 200, f"Failed when trying to obtain agent ID: {response}"
    assert (response['json']['data']['affected_items'][0]['id'] == agent_id and
           response['json']['data']['affected_items'][0]['name'] == agent_name), f"Agent {agent_id} {agent_name}" \
                                                                                 'is not active'

    # Check that expected files exist in each node before removing the agent.
    for file in files:
        for host in file['hosts']:
            result = host_manager.run_shell(
                host, f"test -e {file['path'].format(id=agent_id, name=agent_name)} && echo 'exists'"
            )
            assert result, f"This file should exist in {host} but could not be found: " \
                           f"{file['path'].format(id=agent_id, name=agent_name)}"

    # Check that agent information is in the wdb socket
    for host in test_infra_managers:
        for query in queries:
            result = host_manager.run_command(host,
                                              f"{WAZUH_PATH}/framework/python/bin/python3 "
                                              f"{script_path} '{query.format(id=agent_id)}'")
            assert result, f"This db query should have returned something in {host}, but it did not: {result}"

    # Remove the agent
    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f"/agents?agents_list={agent_id}&status=all&older_than=0s")
    assert response['status'] == 200, f"Failed when trying to remove agent {agent_id}: {response}"

    # Wait until information is synced to all workers
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()
    sleep(time_to_sync)

    # Check that agent-related files where removed from each node.
    for file in files:
        for host in file['hosts']:
            result = host_manager.run_shell(
                host, f"test -e {file['path'].format(id=agent_id, name=agent_name)} && echo 'exists'"
            )
            assert not result, f"This file should not exist in {host} but it was found: " \
                               f"{file['path'].format(id=agent_id, name=agent_name)}"

    # Check that agent information is not in the wdb socket
    for host in test_infra_managers:
        for query in queries:
            result = host_manager.run_command(host,
                                              f"{WAZUH_PATH}/framework/python/bin/python3 "
                                              f"{script_path} '{query.format(id=agent_id)}'")
            assert not result, f"This db query should have not returned anything in {host}, but it did: {result}"
