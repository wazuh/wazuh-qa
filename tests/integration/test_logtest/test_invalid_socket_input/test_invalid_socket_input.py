# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from struct import pack

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'invalid_socket_input.yaml')
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
def test_invalid_socket_input(connect_to_sockets_function, test_case: list):
    """Check that every input message in logtest socket generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys)
    """
    stage = test_case[0]

    if stage["stage"] != 'Oversize message':
        receiver_sockets[0].send(stage['input'], size=True)
    else:
        logtest_max_req_size = 2 ** 16
        oversize_header = pack("<I", logtest_max_req_size)
        receiver_sockets[0].send(stage['input'].format(oversize_header))

    result = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    assert stage['output'] == result, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1,
                                                                             stage['stage'])
