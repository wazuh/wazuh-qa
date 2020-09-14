# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
import json
import ast

from wazuh_testing import global_parameters
from wazuh_testing.analysis import callback_fim_error
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import SocketController


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations    

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'invalid_session_token.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)
    tc=list(test_cases)

# Variables

log_monitor_paths = [LOG_FILE_PATH]
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'logtest'))

receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


def create_connection():
    return SocketController(address=logtest_path, family='AF_UNIX', connection_protocol='TCP')

def close_connection(connection):
    connection.close();


# Tests

@pytest.mark.parametrize('test_case',
                         list(test_cases),
                         ids=[test_case['name'] for test_case in test_cases])
def test_invalid_session_token(test_case):

    errors = []

    for stage in test_case['test_case']:
        
        connection = create_connection();
        
        #Generate logtest request
        request_pattern = '{{ "version":1, \
            "origin":{{"name":"Integration Test","module":"api"}}, \
            "command":"log_processing", \
            "parameters":{{ "token":{} , {} , {} , {} }} \
            }}'
        input = request_pattern.format(stage['input_token'],test_case['input_event'],
            test_case['input_log_format'],test_case['input_location'])

        #Send request
        connection.send(input, size=True)

        #Parse logtest reply as JSON
        result = json.loads(connection.receive(size=True).rstrip(b'\x00').decode())

        close_connection(connection)

        #Get the generated token
        new_token = result["data"]['token']

        #Generate expected message using output template
        expected = json.loads(stage['output'].format(new_token,new_token))

        #Check if invalid token warning message and new token is generated
        if expected['messages'][0].format(stage['input_token']) != result["data"]['messages'][0]:
            errors.append(stage['stage'])
        if expected['messages'][1] != result["data"]['messages'][1]:
            errors.append(stage['stage'])

    assert not errors , "Failed stage(s) :{}".format("\n".join(errors))
