# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
import re

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
