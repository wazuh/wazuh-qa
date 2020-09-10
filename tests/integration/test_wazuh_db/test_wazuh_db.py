# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
import re
import json
import socket
import struct
import sqlite3

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_files = os.listdir(test_data_path)
module_tests = list()
for file in messages_files:
    with open(os.path.join(test_data_path, file)) as f:
        module_tests.append((yaml.safe_load(f), file.split("_")[0]))

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
    return bool(re.match(regex, string))


def insert_agents(id_offset, amount): 
    for id in range(id_offset,id_offset+amount):
        command = f'global insert-agent {{"id":{id},"name":"TestName{id}","date_add":1599223378}}'
        receiver_sockets[0].send(command, size=True)
        response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
                                          callback=callback_wazuhdb_response).result()
        data = response.split(" ", 1)
        if data[0]!='ok':
            raise AssertionError('Unable to add agent {id}')

"""
def insert_agents(id_offset, amount):
    ADDR = '/var/ossec/queue/db/wdb'
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ADDR)

    for id in range(id_offset,id_offset+amount):
        command = f'global insert-agent {{"id":{id},"name":"TestName{id}","date_add":1599223378}}'
        command = struct.pack('<I', len(command)) + command.encode()
        sock.send(command)
        data = sock.recv(4)
        data_size = struct.unpack('<I', data[0:4])[0]
        data = sock.recv(data_size).decode(encoding='utf-8', errors='ignore').split(" ", 1)
        if data[0]!='ok':
            raise AssertionError('Unable to add agent {id}')
"""
"""
def insert_agents(id_offset, amount):
    try:
        sqliteConnection = sqlite3.connect('/var/ossec/queue/db/global.db')
        cursor = sqliteConnection.cursor()       

        for id_ in range(id_offset,id_offset+amount):
            query = f"INSERT INTO agent (id, name, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_platform, date_add, last_keepalive, sync_status) VALUES ({id_},'wazuh-agent{id_}','any','b7efaafcde1bb0f3d3cbbf5b32e6335878305f4e6a19bec2d065f5e53e134e65','Ubuntu','18.04.4 LTS','18','04','Bionic Beaver','ubuntu', 0,0,1)"
            count = cursor.execute(query)

        sqliteConnection.commit()        
        cursor.close()

    except sqlite3.Error as error:
        print("Failed to insert data into sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
            print("The SQLite connection is closed")
"""

# Tests

@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_wazuh_db_messages(configure_sockets_environment, connect_to_sockets_module, test_case: list):
    """Check that every input message in wazuh-db socket generates the adequate output to wazuh-db socket

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """    
    for stage in test_case:
        if 'ignore' in stage and stage['ignore'] == "yes":
            continue
        
        expected = stage['output']
        receiver_sockets[0].send(stage['input'], size=True)
        response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
                                              callback=callback_wazuhdb_response).result()
        
        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = regex_match(expected, response)
        else:
            match = (expected == response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}'\
               .format(test_case.index(stage) + 1, stage['stage'], expected, response)


def test_wazuh_db_create_agent(configure_sockets_environment, connect_to_sockets_module):
    """Check that Wazuh DB creates the agent database when a query with a new agent ID is sent"""
    test = {"name": "Create agent",
            "description": "Wazuh DB creates automatically the agent's database the first time a query with a new agent"
                           " ID reaches it. Once the database is created, the query is processed as expected.",
            "test_case": [{"input": "agent 999 syscheck integrity_check_left",
                           "output": "err Invalid FIM query syntax, near 'integrity_check_left'",
                           "stage": "Syscheck - Agent does not exits yet"}]}
    test_wazuh_db_messages(configure_sockets_environment, connect_to_sockets_module, test['test_case'])
    assert os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'db', "999.db"))

"""
def test_wazuh_db_chunks(configure_mitm_environment, connect_to_sockets_module):
    
    AGENTS_CANT = 14000
    AGENTS_OFFSET = 20
    AGENTS_MAX = AGENTS_OFFSET+AGENTS_CANT
    
    #Pre insert agents
    insert_agents(AGENTS_OFFSET, AGENTS_CANT)
   
    #Check get-all-agents chunk limit
    command = f'global get-all-agents last_id 0'
    receiver_sockets[0].send(command, size=True)
    response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
                                          callback=callback_wazuhdb_response).result()
    
    status = response.split(" ",1)[0]
    assert status == 'due', 'Failed chunks check onget-all-agents. Expected: {}. Response: {}'\
           .format('due', status)
    
    #Check get-agents-by-keepalive chunk limit
    command = f'global get-agents-by-keepalive condition > -1 last_id 0'
    receiver_sockets[0].send(command, size=True)
    response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
                                          callback=callback_wazuhdb_response).result()
    
    status = response.split(" ",1)[0]
    assert status == 'due', 'Failed chunks check on get-agents-by-keepalive. Expected: {}. Response: {}'\
           .format('due', status)

    
    #Check sync-agent-info-get chunk limit
    command = f'global sync-agent-info-get last_id 0'
    receiver_sockets[0].send(command, size=True)
    response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
                                          callback=callback_wazuhdb_response).result()
    
    status = response.split(" ",1)[0]
    assert status == 'due', 'Failed chunks check on sync-agent-info-get. Expected: {}. Response: {}'\
           .format('due', status)
"""