# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import datetime
import os
from os.path import join, dirname, abspath
from time import time

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

master_host = 'wazuh-master'
worker_host = 'wazuh-worker2'
agent_host = 'wazuh-agent3'
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')
managers_hosts = [master_host, worker_host]
inventory_path = join(dirname(dirname(dirname(abspath(__file__)))), 'provisioning', 'basic_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)

# Each file should exist in all hosts specified in 'hosts'.
files = [{'path': join(WAZUH_PATH, 'queue', 'rids', '{id}'), 'hosts': managers_hosts},
         {'path': join(WAZUH_PATH, 'queue', 'agent-groups', '{id}'), 'hosts': managers_hosts},
         {'path': join(WAZUH_PATH, 'queue', 'diff', '{name}'), 'hosts': [worker_host]},
         {'path': join(WAZUH_PATH, 'queue', 'db', '{id}.db'), 'hosts': [worker_host]}]


@pytest.fixture(scope='function')
def register_agent():
    """Restart the removed agent to trigger auto-enrollment."""
    yield
    host_manager.get_host(agent_host).ansible('command', f'service wazuh-agent restart', check=False)

    # Wait until the agent is reconnected
    timeout = time() + 180
    while True:
        if int(host_manager.run_shell('wazuh-worker2',
                                      f'{WAZUH_PATH}/bin/cluster_control -a | '
                                      f'grep active | wc -l')) == 4 and int(host_manager.run_shell('wazuh-master',
                                      f'{WAZUH_PATH}/bin/cluster_control -a | '
                                      f'grep active | wc -l')) == 4 or time() > timeout:
            break
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()


def test_agent_files_deletion(register_agent):
    """Check that when an agent is deleted, all its related files in managers are also removed."""
    # Clean ossec.log and cluster.log
    for hosts in managers_hosts:
        host_manager.clear_file(host=hosts, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
        host_manager.clear_file(host=hosts, file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
        host_manager.control_service(host=hosts, service='wazuh', state="restarted")

    # Get the current ID and name of the agent that is reporting to worker_host.
    master_token = host_manager.get_api_token(master_host)
    response = host_manager.make_api_call(host=master_host, method='GET', token=master_token,
                                          endpoint=f'/agents?select=id,name&q=manager={worker_host}')

    assert response['status'] == 200, f'Failed when trying to obtain agent ID: {response}'
    try:
        agent_id = response['json']['data']['affected_items'][0]['id']
        agent_name = response['json']['data']['affected_items'][0]['name']
    except IndexError as e:
        pytest.fail(f"Could not find any agent reporting to {worker_host}: {response['json']}")

    # Check that expected files exist in each node before removing the agent.
    for file in files:
        for host in file['hosts']:
            result = host_manager.run_shell(
                host, f'test -e {file["path"].format(id=agent_id, name=agent_name)} && echo "exists"'
            )
            assert result, f'This file should exist in {host} but could not be found: ' \
                           f'{file["path"].format(id=agent_id, name=agent_name)}'

    # Check that agent information is in the wdb socket
    query = f'global sql select * from agent where id={agent_id}'
    for host in managers_hosts:
        result = host_manager.run_command(host, f"/var/ossec/framework/python/bin/python3.9 /send_msg.py {query}")
        assert result, f'This db query should have returned something in {host}, but it did not: {result}'

    # Remove the agent
    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f'/agents?agents_list={agent_id}&status=all&older_than=0s')
    assert response['status'] == 200, f'Failed when trying to remove agent {agent_id}: {response}'

    # Wait until information is synced to all workers
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()

    # Check that agent-related files where removed from each node.
    for file in files:
        for host in file['hosts']:
            result = host_manager.run_shell(
                host, f'test -e {file["path"].format(id=agent_id, name=agent_name)} && echo "exists"'
            )
            assert not result, f'This file should not exist in {host} but it was found: ' \
                               f'{file["path"].format(id=agent_id, name=agent_name)}'

    # Check that agent information is not in the wdb socket
    for host in managers_hosts:
        result = host_manager.run_command(host,
                                          f"/var/ossec/framework/python/bin/python3.9 /send_msg.py {query}")
        assert not result, f'This db query should have not returned anything in {host}, but it did: {result}'
