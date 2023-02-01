# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
from os.path import join, dirname, abspath
from time import time, sleep

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

master_host = 'wazuh-master'
worker_host = 'wazuh-worker2'
agent_host = 'wazuh-agent3'
pytestmark = [pytest.mark.cluster]
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
script_path = os.path.join(re.sub(r'^.*?wazuh-qa', '/wazuh-qa', local_path), '../utils/get_wdb_agent.py')

tmp_path = os.path.join(local_path, 'tmp')
managers_hosts = [master_host, worker_host]
inventory_path = join(dirname(dirname(dirname(abspath(__file__)))), 'provisioning', 'basic_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
while_time = 5
time_to_sync = 20
time_to_agent_reconnect = 180

# Each file should exist in all hosts specified in 'hosts'.
files = [{'path': join(WAZUH_PATH, 'queue', 'rids', '{id}'), 'hosts': managers_hosts},
         {'path': join(WAZUH_PATH, 'queue', 'diff', '{name}'), 'hosts': [worker_host]},
         {'path': join(WAZUH_PATH, 'queue', 'db', '{id}.db'), 'hosts': [worker_host]}]

queries = ['global sql select * from agent where id={id}',
           'global sql select * from belongs where id_agent={id}']


def agent_healthcheck(master_token):
    """Check if the agent is active and reporting."""
    timeout = time() + time_to_agent_reconnect
    healthy = False

    while not healthy:
        response = host_manager.make_api_call(host=master_host, method='GET', token=master_token,
                                              endpoint='/agents?status=active')

        assert response['status'] == 200, 'Failed when trying to get the active agents'
        if int(response['json']['data']['total_affected_items']) == 4:
            for item in response['json']['data']['affected_items']:
                if item['name'] == agent_host and item['manager'] == worker_host:
                    healthy = True
        elif time() > timeout:
            raise TimeoutError("The agent 'wazuh-agent3' is not 'Active' yet.")
        sleep(while_time)
    sleep(time_to_sync)


def test_agent_files_deletion():
    """Check that when an agent is deleted, all its related files in managers are also removed."""
    # Clean ossec.log and cluster.log
    for hosts in managers_hosts:
        host_manager.clear_file(host=hosts, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
        host_manager.clear_file(host=hosts, file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
        host_manager.control_service(host=hosts, service='wazuh', state='restarted')

    # Get the token
    master_token = host_manager.get_api_token(master_host)

    # Check if the agent is connected and reporting
    agent_healthcheck(master_token)

    # Get the current ID and name of the agent that is reporting to worker_host.
    response = host_manager.make_api_call(host=master_host, method='GET', token=master_token,
                                          endpoint=f"/agents?select=id,name&q=manager={worker_host}")

    assert response['status'] == 200, f"Failed when trying to obtain agent ID: {response}"
    try:
        agent_id = response['json']['data']['affected_items'][0]['id']
        agent_name = response['json']['data']['affected_items'][0]['name']
    except IndexError as e:
        pytest.fail(f"Could not find any agent reporting to {worker_host}: {response['json']}")

    # Check that expected files exist in each node before removing the agent.
    for file in files:
        for host in file['hosts']:
            result = host_manager.run_shell(
                host, f"test -e {file['path'].format(id=agent_id, name=agent_name)} && echo 'exists'"
            )
            assert result, f"This file should exist in {host} but could not be found: " \
                           f"{file['path'].format(id=agent_id, name=agent_name)}"

    # Check that agent information is in the wdb socket
    for host in managers_hosts:
        for query in queries:
            result = host_manager.run_command(host,
                                              f"{WAZUH_PATH}/framework/python/bin/python3.9 "
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
    for host in managers_hosts:
        for query in queries:
            result = host_manager.run_command(host,
                                              f"{WAZUH_PATH}/framework/python/bin/python3.9 "
                                              f"{script_path} '{query.format(id=agent_id)}'")
            assert not result, f"This db query should have not returned anything in {host}, but it did: {result}"

    host_manager.control_service(host=agent_host, service='wazuh', state='restarted')
    agent_healthcheck(master_token)
