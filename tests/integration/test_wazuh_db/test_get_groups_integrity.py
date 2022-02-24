'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the get-groups-integrity command used to determine if the agent groups are synced 
       or if a sync is needed.

tier: 0

modules:
    - wazuh_db

components:
    - manager

daemons:
    - wazuh-db

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html

tags:
    - wazuh_db
'''
import os
import time
import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import query_wdb, insert_agent_in_db, remove_agent

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_file = os.path.join(test_data_path, 'get_groups_integrity_messages.yaml')
module_tests = []
with open(messages_file) as f:
    module_tests.append((yaml.safe_load(f), messages_file.split('_')[0]))

log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets= None  # Set in the fixtures


# Tests
@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_set_agent_groups(configure_sockets_environment, connect_to_sockets_module, test_case):
    '''
    description: Check that every input message using the 'get-groups-integrity' command in wazuh-db socket generates 
                 the proper output to wazuh-db socket. To do this, it performs a query to the socket with a command 
                 taken from the list of test_cases's 'input' field, and compare the result with the test_case's
                 'output' field. 

    wazuh_min_version: 4.4.0

    parameters:
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - test_case:
            type: fixture
            brief: List of test_case stages (dicts with input, output and agent_id and expected_groups keys).

    assertions:
        - Verify that the socket response matches the expected output.

    input_description:
        - Test cases are defined in the get_groups_integrity_messages.yaml file. This file contains the agent id's to
          register, as well as the group_sync_status that each agent will have, as well as the expected output and 
          result for the test.

    expected_output:
        - f"Assertion Error - expected {output}, but got {response}"
        - f'Unexpected response: got {response}, but expected {output}'
        - 'Unable to add agent'

    tags:
        - wazuh_db
        - wdb_socket
    '''

    case_data = test_case[0]
    output = case_data["output"]
    agent_ids= case_data["agent_ids"]
    agent_status= case_data["agent_status"]

    # Insert test Agents
    for index, id in enumerate(agent_ids):
        response = insert_agent_in_db(id=id+1, connection_status="disconnected", 
                                      registration_time=str(time.time()))
        command = f'global set-agent-groups {{"mode":"append","sync_status":"{agent_status[index]}","source":"remote",\
                    "data":[{{"id":{id},"groups":["Test_group{id}"]}}]}}'
        response =  query_wdb(command)

    # Get database hash
    if "invalid_hash" in case_data:
        hash = case_data["invalid_hash"]
    else:
        response = query_wdb(f'global sync-agent-groups-get {{"last_id": 0, "condition": "all", "get_global_hash": true, \
                             "set_synced": false, "agent_delta_registration": 0}}')
        if "no_hash" in case_data:
            assert response == output, f'Unexpected response: got {response}, but expected {output}'
            return
        response = response[0]
        hash = response["hash"]

    # Get groups integrity
    response = query_wdb(f"global get-groups-integrity {hash}")
    if isinstance(response, list):
        response = response[0]

    # validate output
    assert response == output, f"Assertion Error - expected {output}, but got {response}"

    # Remove test agents
    for id in agent_ids:
        remove_agent(id)
