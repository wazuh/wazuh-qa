# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import socket
import ssl

from wazuh_testing import global_parameters, logger
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from conftest import load_tests
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'manager_conf.yaml')
params = [{'force_insert': 'yes'}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params)



# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-db', None, True), ('ossec-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures



# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('message, output, stage', [
    ("OSSEC A:'user1'", 'any' , 'user1 auth default'),
])
def test_ossec_auth_manager_create_key(message, output, stage, get_configuration, configure_environment, configure_mitm_environment, 
                                        connect_to_sockets_module, wait_for_agentd_startup):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """    
    
    # Reopen socket (socket is closed by maanger after sending message with client key)
    receiver_sockets[0].open()
    receiver_sockets[0].send(message, size=False)
    response = receiver_sockets[0].receive().decode()
    assert response, 'Failed connection stage: {}'.format(stage)
    assert output in response, 'Failed test case stage: {}'.format(stage)
    assert 'ERROR' not in response, 'Failed test case stage: {}'.format(stage)
    


@pytest.mark.parametrize('message, output, stage', [
    ("OSSEC A:'user1' IP:'10.10.10.10'", '10.10.10.10' , 'user1 auth with IP')
])
def test_ossec_auth_manager_create_key_with_IP(message, output, stage, get_configuration, configure_environment, configure_mitm_environment, 
                                                        connect_to_sockets_module, wait_for_agentd_startup):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """    
    
    
    # Reopen socket (socket is closed by maanger after sending message with client key)
    receiver_sockets[0].open()     
    receiver_sockets[0].send(message, size=False)
    response = receiver_sockets[0].receive().decode()
    assert response, 'Failed connection stage: {}'.format(stage)
    assert output in response, 'Failed test case stage: {}'.format(stage)
    assert 'ERROR' not in response, 'Failed test case stage: {}'.format(stage)