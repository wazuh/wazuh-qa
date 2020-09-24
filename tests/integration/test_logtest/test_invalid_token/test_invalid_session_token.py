# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
import json

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import SocketController
from wazuh_testing.logtest import callback_session_initialized, callback_invalid_token


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'invalid_session_token.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)
    tc=list(test_cases)


# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'logtest'))


# Functions used on the test

def create_connection():
    return SocketController(address=logtest_path, family='AF_UNIX', connection_protocol='TCP')

def close_connection(connection):
    connection.close()


# Tests

@pytest.mark.parametrize('test_case',
                         list(test_cases),
                         ids=[test_case['name'] for test_case in test_cases])
def test_invalid_session_token(test_case):

    errors = []

    for stage in test_case['test_case']:
        
        connection = create_connection();
        
        #Generate logtest request
        request_pattern = """{{ "version":1,
            "origin":{{"name":"Integration Test","module":"api"}},
            "command":"log_processing",
            "parameters":{{ "token":{} , {} , {} , {} }}
            }}"""

        input = request_pattern.format(stage['input_token'],
                                       test_case['input_event'],
                                       test_case['input_log_format'],
                                       test_case['input_location'])

        #Send request
        connection.send(input, size=True)

        #Parse logtest reply as JSON
        result = json.loads(connection.receive(size=True).rstrip(b'\x00').decode())

        close_connection(connection)

        #Get the generated token
        new_token = result["data"]['token']

        #Check if invalid token warning message and new token is generated
        match = callback_invalid_token(result["data"]['messages'][0])
        if match == None:
            errors.append(stage['stage'])

        match = callback_session_initialized(result["data"]['messages'][1])
        if match == None:
            errors.append(stage['stage'])

    assert not errors , "Failed stage(s) :{}".format("\n".join(errors))
