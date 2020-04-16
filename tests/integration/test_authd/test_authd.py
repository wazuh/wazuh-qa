# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH
import socket
import ssl


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


# Tests

@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )

def test_wazuh_db_messages(test_case: list):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """    

    for stage in test_case:
        expected = stage['output']       
        message = stage['input']

        response = send_enrollment(message)  
        assert response, 'Failed connection stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
        assert response[:len(expected)] == expected, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
    

def send_enrollment(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH")
    wrappedSocket.connect((socket.gethostname(), 1515))
    wrappedSocket.send(message.encode())
    response = wrappedSocket.recv(1280).decode()
    wrappedSocket.close()
    return response