# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os.path import join, dirname, abspath
from time import sleep

import pytest

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.system import HostManager

master_host = 'wazuh-master'
worker_host = 'wazuh-worker2'
agent_host = 'wazuh-agent3'
managers_hosts = [master_host, worker_host]
inventory_path = join(dirname(dirname(dirname(abspath(__file__)))), 'provisioning', 'basic_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
time_to_sync = 60

# Each file should exist in all hosts specified in 'hosts'.
files = [{'path': join(WAZUH_PATH, 'queue', 'rids', '{id}'), 'hosts': managers_hosts},
         {'path': join(WAZUH_PATH, 'queue', 'agent-groups', '{id}'), 'hosts': managers_hosts},
         {'path': join(WAZUH_PATH, 'queue', 'diff', '{name}'), 'hosts': [worker_host]},
         {'path': join(WAZUH_PATH, 'queue', 'db', '{id}.db'), 'hosts': [worker_host]}]
db_queries = ["select * from agent where id={id}",
              "select * from belongs where id_agent={id}"]


@pytest.fixture(scope='function')
def register_agent():
    """Restart the removed agent to trigger auto-enrollment."""
    yield
    host_manager.get_host(agent_host).ansible('command', f'service wazuh-agent restart', check=False)


def test_agent_files_deletion(register_agent):
    """Check that when an agent is deleted, all its related files in managers are also removed."""
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

    # Check that agent information exists in global.db
    for host in managers_hosts:
        for query in db_queries:
            result = host_manager.run_command(
                host,
                f'sqlite3 {join(WAZUH_PATH, "queue", "db", "global.db")} "{query.format(id=agent_id, name=agent_name)}"'
            )
            assert result, f'This db query should have returned something in {host}, but it did not: ' \
                           f'{query.format(id=agent_id, name=agent_name)}'

    response = host_manager.make_api_call(host=master_host, method='DELETE', token=master_token,
                                          endpoint=f'/agents?agents_list={agent_id}&status=all&older_than=0s')
    assert response['status'] == 200, f'Failed when trying to remove agent {agent_id}: {response}'

    # Wait until information is synced to all workers
    sleep(time_to_sync)

    # Check that agent-related files where removed from each node.
    for file in files:
        for host in file['hosts']:
            result = host_manager.run_shell(
                host, f'test -e {file["path"].format(id=agent_id, name=agent_name)} && echo "exists"'
            )
            assert not result, f'This file should not exist in {host} but it was found: ' \
                               f'{file["path"].format(id=agent_id, name=agent_name)}'

    # Check that agent information does not exist anymore in global.db
    for host in managers_hosts:
        for query in db_queries:
            result = host_manager.run_command(
                host,
                f'sqlite3 {join(WAZUH_PATH, "queue", "db", "global.db")} "{query.format(id=agent_id, name=agent_name)}"'
            )
            assert not result, f'This db query should have not returned anything in {host}, but it did: ' \
                               f'{query.format(id=agent_id, name=agent_name)} -> {result}'
