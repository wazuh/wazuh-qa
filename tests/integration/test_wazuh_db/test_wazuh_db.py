# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import time
import pytest
import yaml
import json
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import make_callback, WAZUH_DB_PREFIX
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.tools.services import control_service, delete_dbs
from wazuh_testing.tools.wazuh_manager import remove_all_agents

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
agent_message_files = os.path.join(test_data_path, 'agent')
global_message_files = os.path.join(test_data_path, 'global')

agent_module_tests = []
global_module_tests = []

for file in os.listdir(agent_message_files):
    with open(os.path.join(agent_message_files, file)) as f:
        agent_module_tests.append((yaml.safe_load(f), file.split('_')[0]))

for file in os.listdir(global_message_files):
    with open(os.path.join(global_message_files, file)) as f:
        global_module_tests.append((yaml.safe_load(f), file.split('_')[0]))

# Variables
log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT = 20

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
    regex = regex.replace('*', '.*')
    regex = regex.replace('[', '')
    regex = regex.replace(']', '')
    regex = regex.replace('(', '')
    regex = regex.replace(')', '')
    string = string.replace('[', '')
    string = string.replace(']', '')
    string = string.replace('(', '')
    string = string.replace(')', '')
    return re.match(regex, string)


@pytest.fixture(scope="module")
def clean_registered_agents():
    remove_all_agents('wazuhdb')
    time.sleep(5)


@pytest.fixture(scope='module')
def wait_range_checksum_avoided(line):
    """Callback function to wait until the manager avoided the checksum calculus by using the last saved one."""
    if 'range checksum avoided' in line:
        return line
    return None


def wait_range_checksum_calculated(line):
    """Callback function to wait until the manager calculates the new checksum."""
    if 'range checksum: Time: ' in line:
        return line
    return None


@pytest.fixture(scope="function")
def prepare_range_checksum_data():
    AGENT_ID = 1
    insert_agent(AGENT_ID)
    command = f'agent {AGENT_ID} syscheck save2 '
    payload = {'path': "file",
               'timestamp': 1575421292,
               'attributes': {
                   'type': 'file',
                   'size': 0,
                   'perm': 'rw-r--r--',
                   'uid': '0',
                   'gid': '0',
                   'user_name': 'root',
                   'group_name': 'root',
                   'inode': 16879,
                   'mtime': 1575421292,
                   'hash_md5': 'd41d8cd98f00b204e9800998ecf8427e',
                   'hash_sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                   'hash_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                   'checksum': 'f65b9f66c5ef257a7566b98e862732640d502b6f'}}

    payload['path'] = '/home/test/file1'
    execute_wazuh_db_query(command+json.dumps(payload))
    payload['path'] = '/home/test/file2'
    execute_wazuh_db_query(command+json.dumps(payload))

    yield

    remove_agent(AGENT_ID)


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


@pytest.fixture(scope='function')
def insert_agents_test():
    """Insert agents. Only used for the agent queries"""
    agent_list = [1, 2]
    for agent in agent_list:
        insert_agent(agent)

    yield

    for agent in agent_list:
        remove_agent(agent)


@pytest.fixture(scope='module')
def restart_wazuh(request):
    control_service('start')
    yield

    delete_dbs()
    control_service('stop')


def execute_wazuh_db_query(command):
    """Function to send a command to the wazuh-db socket.
    Args:
        command(str): Message to send to the socket.
    Returns:
        str: A response from the socket
    """
    receiver_sockets[0].send(command, size=True)
    return receiver_sockets[0].receive(size=True).decode()


def insert_agent(agent_id, agent_name='TestName'):
    """Function that wraps the needed queries to register an agent.
    Args:
        agent_id(int): Unique identifier of an agent
    Raises:
        AssertionError: If the agent couldn't be inserted in the DB
    """
    insert_data = json.dumps({'id': agent_id,
                              'name': f"{agent_name}{agent_id}",
                              'date_add': 1599223378
                              })

    update_data = json.dumps({'id': agent_id,
                              'sync_status': 'syncreq',
                              'connection_status': 'active'
                              })

    command = f"global insert-agent {insert_data}"
    data = execute_wazuh_db_query(command).split(' ', 1)
    assert data[0] == 'ok', f"Unable to add agent {agent_id} - {data[1]}"

    command = f"global update-keepalive {update_data}"
    data = execute_wazuh_db_query(command).split(' ', 1)
    assert data[0] == 'ok', f"Unable to update agent {agent_id} - {data[1]}"


def remove_agent(agent_id):
    """Function that wraps the needed queries to remove an agent.
    Args:
        agent_id(int): Unique identifier of an agent
    """
    data = execute_wazuh_db_query(f"global delete-agent {agent_id}").split(' ', 1)
    assert data[0] == 'ok', f"Unable to remove agent {agent_id} - {data[1]}"


# Tests

@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in agent_module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in agent_module_tests
                              for case in module_data]
                         )
def test_wazuh_db_messages_agent(restart_wazuh, clean_registered_agents, configure_sockets_environment,
                                 connect_to_sockets_module, insert_agents_test, test_case):
    """Check that every input agent message in wazuh-db socket generates the adequate output to wazuh-db socket.

    Args:
        test_case(list): List of test_case stages (dicts with input, output and stage keys).
    """
    for index, stage in enumerate(test_case):
        if 'ignore' in stage and stage['ignore'] == 'yes':
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
def test_wazuh_db_messages_global(connect_to_sockets_module, restart_wazuh, test_case):
    """Check that every input global message in wazuh-db socket generates the adequate output to wazuh-db socket.

    Args:
        test_case(list): List of test_case stages (dicts with input, output and stage keys).
    """
    for index, stage in enumerate(test_case):
        if 'ignore' in stage and stage['ignore'] == 'yes':
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


def test_wazuh_db_chunks(restart_wazuh, configure_sockets_environment, clean_registered_agents,
                         connect_to_sockets_module, pre_insert_agents):
    """Check that commands by chunks work properly when agents amount exceed the response maximum size"""
    def send_chunk_command(command):
        response = execute_wazuh_db_query(command)
        status = response.split(' ', 1)[0]

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


def test_wazuh_db_range_checksum(restart_wazuh, configure_sockets_environment, connect_to_sockets_module,
                                 prepare_range_checksum_data, file_monitoring, request):
    """Check the checksum range during the synchroniation of the DBs"""
    command = """agent 1 syscheck integrity_check_global {\"begin\":\"/home/test/file1\",\"end\":\"/home/test/file2\",
                 \"checksum\":\"2a41be94762b4dc57d98e8262e85f0b90917d6be\",\"id\":1}"""
    log_monitor = request.module.log_monitor
    # Checksum Range calculus expected the first time
    execute_wazuh_db_query(command)
    log_monitor.start(timeout=WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT,
                      callback=make_callback('range checksum: Time: ', prefix=WAZUH_DB_PREFIX,
                                             escape=True),
                      error_message='Checksum Range wasn´t calculated the first time')

    # Checksum Range avoid expected the next times
    execute_wazuh_db_query(command)
    log_monitor.start(timeout=WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT,
                      callback=make_callback('range checksum avoided', prefix=WAZUH_DB_PREFIX,
                                             escape=True),
                      error_message='Checksum Range wasn´t avoided the second time')
