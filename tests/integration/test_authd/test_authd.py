# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import socket
import ssl

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH
from conftest import load_tests
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = load_tests(os.path.join(test_data_path, 'enroll_messages.yaml'))



# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-db', None, True), ('ossec-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
# Tests

@pytest.mark.parametrize('test_case', [case['test_case'] for case in message_tests])
def test_ossec_auth_messages( configure_mitm_environment, connect_to_sockets_module, wait_for_agentd_startup, test_case: list):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """    
    for stage in test_case:
        # Reopen socket (socket is closed by maanger after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['output']       
        message = stage['input']
        receiver_sockets[0].send(stage['input'], size=False)
        response = receiver_sockets[0].receive().decode()
        assert response, 'Failed connection stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
        assert response[:len(expected)] == expected, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
