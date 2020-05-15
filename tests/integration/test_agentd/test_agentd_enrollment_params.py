# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import ssl

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.security import CertificateController
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

mitm = ManInTheMiddle(address=(SERVER_ADDRESS, 1515), family='AF_INET', connection_protocol='SSL')


monitored_sockets_params = [('ossec-agentd', mitm, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="module")
def generate_manager_certificate(get_configuration):
    # Generate root key and certificate
    controller = CertificateController()
    controller.store_private_key(controller.get_root_key(), SERVER_KEY_PATH)
    controller.store_ca_certificate(controller.get_root_ca_cert(), SERVER_CERT_PATH)
    

# Tests
def test_agentd_enrollment_params(generate_manager_certificate, configure_environment, configure_mitm_environment):
    mitm.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2)
    return