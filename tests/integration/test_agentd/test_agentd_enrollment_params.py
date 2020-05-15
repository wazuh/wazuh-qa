# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os

from wazuh_testing.tools.configuration import load_wazuh_configurations
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
params = [
{
    'SERVER_ADDRESS': SERVER_ADDRESS,
    'REMOTED_PORT': REMOTED_PORT,
    'PROTOCOL' : 'udp',
    'ENABLED' : 'yes',
    'AGENT_NAME': 'test_agent',
    'AGENT_ADRESS' : '127.0.0.1',
    'GROUPS': 'test_group',
    'SSL_CIPHER': 'HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH'
}
]
metadata = [{}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

log_monitor_paths = []

receiver_sockets_params = [((SERVER_ADDRESS, 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('ossec-agentd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

# Tests

def test_authd_ssl_certs(get_configuration):
    return