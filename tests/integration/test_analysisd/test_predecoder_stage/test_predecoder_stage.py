'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon receives the log messages and compares them to the rules.
       It then creates an alert when a log message matches an applicable rule.
       Specifically, these tests will verify if the pre-decoding stage of 'wazuh-analysisd' daemon correctly handles
       syslog formats.

components:
    - analysisd

suite: predecoder_stage

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

'''

import os

import pytest
import yaml
import json
from wazuh_testing.tools import WAZUH_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'syslog_socket_input.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]
receiver_sockets = None  # Set in the fixtures


# Tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_precoder_supported_formats(connect_to_sockets_function, test_case: list):
    '''
    description: Check that the predecoder returns the correct fields when receives different sets of syslog formats.
                 To do this, it receives syslog format and checks that the predecoder JSON responses
                 are the same that the loaded ouput for each test case from the 'syslog_socket_input.yaml' file.

    wazuh_min_version: 4.3.0

    tier: 2

    parameters:
        -  connect_to_sockets_function:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.
        - test_case:
            type: list
            brief: List of tests to be performed.

    assertions:
        - Checks that the predecoder gives the expected output.

    input_description: Different test cases that are contained in an external YAML file (syslog_socket_input.yaml)
                       that includes syslog events data and the expected precoder output.

    expected_output:
        - Precoder JSON with the correct fields (timestamp, program name, etc) corresponding to each test case.
    '''
    stage = test_case[0]

    receiver_sockets[0].send(stage['input'], size=True)

    result = json.loads(receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode())

    assert json.loads(stage['output']) == result["data"]["output"]["predecoder"], \
        'Failed test case stage {}: the receved precoded is: {} but was expected to be {}' \
        .format(test_case.index(stage) + 1, result["data"]["output"]["predecoder"], stage['output'])
