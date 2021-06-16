# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import time

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.wazuh_manager import remove_all_agents

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
agent_message_files = os.path.join(test_data_path, 'agent')
global_message_files = os.path.join(test_data_path, 'global')

agent_module_tests = list()
global_module_tests = list()

for file in os.listdir(agent_message_files):
    with open(os.path.join(agent_message_files, file)) as f:
        agent_module_tests.append((yaml.safe_load(f), file.split("_")[0]))

for file in os.listdir(global_message_files):
    with open(os.path.join(global_message_files, file)) as f:
        global_module_tests.append((yaml.safe_load(f), file.split("_")[0]))

# Variables

log_monitor_paths = []

wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))

receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]

# mitm_analysisd = ManInTheMiddle(address=analysis_path, family='AF_UNIX', connection_protocol='UDP')
# monitored_sockets_params is a List of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [('wazuh-db', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


def regex_match(regex, string):
    regex = regex.replace("*", ".*")
    regex = regex.replace("[", "")
    regex = regex.replace("]", "")
    regex = regex.replace("(", "")
    regex = regex.replace(")", "")
    string = string.replace("[", "")
    string = string.replace("]", "")
    string = string.replace("(", "")
    string = string.replace(")", "")
    return re.match(regex, string)


@pytest.fixture(scope="module")
def clean_registered_agents():
    remove_all_agents('wazuhdb')
    time.sleep(5)


@pytest.fixture(scope="module")
def restart_wazuh():
    control_service('restart')

def execute_wazuh_db_query(command: str):
    """Function to send a command to the wazuh-db socket.
    Args:
        command(str): Message to send to the socket.
    Returns
        A response from the socket
    """
    receiver_sockets[0].send(command, size=True)
    return receiver_sockets[0].receive(size=True).decode()


def insert_agent(agent_id: int):
    """Function that wraps the needed queries to register an agent
    Args:
        agent_id(int): Unique identifier of an agent
    Raises:
        AssertionError: If the agent couldn't be inserted in the DB
    """
    command = f'global insert-agent {{"id":{agent_id},"name":"TestName{agent_id}","date_add":1599223378}}'
    data = execute_wazuh_db_query(command).split(" ", 1)

    assert data[0] == 'ok', f'Unable to add agent {agent_id} - {data[1]}'

    command = f'global update-keepalive {{"id":{agent_id},"sync_status":"syncreq","connection_status":"active"}}'
    data = execute_wazuh_db_query(command).split(" ", 1)

    assert data[0] == 'ok', f'Unable to update agent {agent_id} - {data[1]}'


def remove_agent(agent_id: int):
    """Function that wraps the needed queries to remove an agent.
    Args:
        agent_id(int): Unique identifier of an agent
    """
    execute_wazuh_db_query(f'global delete-agent {agent_id}')


# Tests


@pytest.fixture(scope="function")
def pre_insert_agents():
    """Insert agents. Only used for the global queries"""
    AGENTS_CANT = 14000
    AGENTS_OFFSET = 20
    for id in range(AGENTS_OFFSET, AGENTS_OFFSET + AGENTS_CANT):
        insert_agent(id)

    yield

    for id in range(AGENTS_OFFSET, AGENTS_OFFSET + AGENTS_CANT):
        remove_agent(id)


@pytest.fixture(scope="function")
def insert_agents_test():
    """Insert agents. Only used for the agent queries"""
    agent_list = [1, 2]
    for agent in agent_list:
        insert_agent(agent)

    yield

    for agent in agent_list:
        remove_agent(agent)


@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in agent_module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in agent_module_tests
                              for case in module_data]
                         )
def test_wazuh_db_messages_agent(restart_wazuh, clean_registered_agents, configure_sockets_environment, connect_to_sockets_module, insert_agents_test,
                                 test_case: list):
    """Check that every input agent message in wazuh-db socket generates the adequate output to wazuh-db socket

    Args:
        test_case(list): List of test_case stages (dicts with input, output and stage keys).
    """
    for index, stage in enumerate(test_case):
        if 'ignore' in stage and stage['ignore'] == "yes":
            continue

        command = stage['input']
        expected_output = stage['output']

        response = execute_wazuh_db_query(command)

        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = True if regex_match(expected_output, response) else False
        else:
            match = (expected_output == response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}' \
            .format(index + 1, stage['stage'], expected_output, response)


@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in global_module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in global_module_tests
                              for case in module_data]
                         )
def test_wazuh_db_messages_global(configure_sockets_environment, connect_to_sockets_module, test_case: list):
    """Check that every input global message in wazuh-db socket generates the adequate output to wazuh-db socket

    Args:
        test_case(list): List of test_case stages (dicts with input, output and stage keys).
    """
    for index, stage in enumerate(test_case):
        if 'ignore' in stage and stage['ignore'] == "yes":
            continue

        command = stage['input']
        expected_output = stage['output']

        response = execute_wazuh_db_query(command)

        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = True if regex_match(expected_output, response) else False
        else:
            match = (expected_output == response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}' \
            .format(index + 1, stage['stage'], expected_output, response)


def test_wazuh_db_create_agent(restart_wazuh, clean_registered_agents, configure_sockets_environment, connect_to_sockets_module):
    """Check that Wazuh DB creates the agent database when a query with a new agent ID is sent"""
    test = {"name": "Create agent",
            "description": "Wazuh DB creates automatically the agent's database the first time a query with a new agent"
                           " ID reaches it. Once the database is created, the query is processed as expected.",
            "test_case": [{"input": "agent 999 syscheck integrity_check_left",
                           "output": "err Invalid FIM query syntax, near 'integrity_check_left'",
                           "stage": "Syscheck - Agent does not exits yet"}]}
    test_wazuh_db_messages_agent(clean_registered_agents, restart_wazuh, configure_sockets_environment, connect_to_sockets_module, test['test_case'])
    assert os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'db', "999.db"))


def test_wazuh_db_chunks(restart_wazuh, clean_registered_agents, configure_sockets_environment, connect_to_sockets_module, pre_insert_agents):
    """Check that commands by chunks work properly when agents amount exceed the response maximum size"""

    def send_chunk_command(command):
        response = execute_wazuh_db_query(command)
        status = response.split(" ", 1)[0]

        assert status == 'due', 'Failed chunks check on < {} >. Expected: {}. Response: {}' \
            .format(command, 'due', status)

    # Check get-all-agents chunk limit
    send_chunk_command('global get-all-agents last_id 0')
    # Check sync-agent-info-get chunk limit
    send_chunk_command('global sync-agent-info-get last_id 0')
    # Check get-agents-by-connection-status chunk limit
    send_chunk_command('global get-agents-by-connection-status 0 active')
    # Check disconnect-agents chunk limit
    send_chunk_command('global disconnect-agents 0 {} syncreq'.format(str(int(time.time()) + 1)))
