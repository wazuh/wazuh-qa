'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the set_agent_groups command used for changing the agent's group data and for the
       cluster's database sync procedures.

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
from wazuh_testing.wazuh_db import query_wdb, insert_agent_in_db
from wazuh_testing.tools.services import delete_dbs

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_file = os.path.join(test_data_path, 'set_agent_groups.yaml')
module_tests = []
with open(messages_file) as f:
    module_tests.append((yaml.safe_load(f), messages_file.split('_')[0]))

log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets= None  # Set in the fixtures


#Fixtures
@pytest.fixture(scope='module')
def remove_database(request):
    yield
    delete_dbs()


# Tests
@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_set_agent_groups(remove_database, configure_sockets_environment, connect_to_sockets_module, test_case):
    '''
    description: Check that every input message using the 'set_agent_groups' command in wazuh-db socket generates 
                 the proper output to wazuh-db socket. To do this, it performs a query to the socket with a command 
                 taken from the list of test_cases's 'input' field, and compare the result with the test_case's
                 'output' and 'expected_group' fields.

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
        - Verify that the agent has the expected_group assigned.

    input_description:
        - Test cases are defined in the set_agent_groups.yaml file. This file contains the command to insert the agentes
          groups, with different modes and combinations, as well as the expected outputs and results.

    expected_output:
        - f"Assertion Error - expected {output}, but got {response}"
        - 'Unable to add agent'
        - 'did not recieve expected groups in Agent.'

    tags:
        - wazuh_db
        - wdb_socket
    '''

    case_data = test_case[0]
    output = case_data["output"]
    agent_id= case_data["agent_id"]

    # Insert test Agent
    response = insert_agent_in_db(id=agent_id, connection_status="disconnected", registration_time=str(time.time()))
    
    # Apply preconditions
    if 'pre_input' in case_data:
        query_wdb(case_data['pre_input'])
    
    # Add tested group
    response = query_wdb(case_data["input"])

    # validate output
    assert response == output, f"Assertion Error - expected {output}, but got {response}"

    # get agent data and validate agent's groups
    response = query_wdb(f'global get-agent-info {agent_id}')

    if case_data["expected_group"] == 'None' and 'err' in output:
        assert 'group' not in response[0], "Agent has groups data and it was expecting no group data"
    else:
        assert case_data["expected_group"] == response[0]['group'], "did not recieve expected groups in Agent."
