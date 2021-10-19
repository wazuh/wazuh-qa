# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import SocketController
from wazuh_testing.tools.monitoring import close_sockets

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'remove_session.yaml')

with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]
receiver_sockets = None  # Set in the fixtures


def create_session():
    msg = """{"version":1,"origin":{"name":"Integration Test","module":"api"},
        "command":"log_processing","parameters":{"event":"Jun 24 11:54:19 Master systemd[2099]:
        Started VTE child process 20118 launched by terminator process 17756.","log_format":"syslog",
        "location":"master->/var/log/syslog"}}"""

    receiver_sockets[0].send(msg, size=True)
    token = json.loads(receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode())['data']['token']

    # Close socket
    close_sockets(receiver_sockets)

    # Renew socket for future connections
    receiver_sockets[0] = SocketController(address=logtest_path, family='AF_UNIX', connection_protocol='TCP')
    return token


# Tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_remove_session(connect_to_sockets_function, test_case: list):
    """Check that every input message in logtest socket generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys)
    """
    stage = test_case[0]

    if stage["stage"] != 'Remove session OK':
        receiver_sockets[0].send(stage['input'], size=True)
        reply = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
        expected = json.loads(stage['output'])
    else:
        session_token = create_session()
        receiver_sockets[0].send(stage['input'].format(session_token), size=True)
        reply = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
        expected = json.loads(stage['output'].format(session_token))

    result = json.loads(reply)
    if 'messages' in expected['data'] and 'messages' in result['data']:
        message_expected = expected['data']['messages'][0]
        message_recieved = result['data']['messages'][0]
        if message_recieved.split(': ')[-1] == message_expected.split(': ')[-1]:
            expected['data']['messages'][0] = result['data']['messages'][0]

    assert expected == result, 'Failed test case stage {}: {}'.format(
        test_case.index(stage) + 1,
        stage['stage'])
