# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.enrollment import EnrollmentSimulator
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514
SERVER_KEY_PATH = '/etc/manager.key'
SERVER_CERT_PATH = '/etc/manager.cert'

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
params = [
{
    'SERVER_ADDRESS': SERVER_ADDRESS,
    'REMOTED_PORT': REMOTED_PORT,
    'PROTOCOL' : 'udp',
    'ENABLED' : 'yes',
    'AGENT_NAME': 'test_agent',
    'AGENT_ADDRESS' : '127.0.0.1',
    'GROUPS': 'test_group',
    'SSL_CIPHER': 'HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH'
}
]
metadata = [{'GROUPS': 'test_group',}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

log_monitor_paths = []


receiver_sockets_params = []

monitored_sockets_params = [('ossec-agentd', None,True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

enrollment_server = EnrollmentSimulator(server_address=SERVER_ADDRESS, remoted_port=REMOTED_PORT, key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="module")
def configure_enrollment_server(request):
    enrollment_server.start()

    yield

    enrollment_server.shutdown()

# Tests
def test_agentd_enrollment_params(configure_enrollment_server, configure_environment, configure_mitm_environment):
    return