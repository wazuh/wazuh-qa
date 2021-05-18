# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import netifaces


from wazuh_testing.api import compare_config_api_response
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = []
metadata = []

# Get all network interfaces ips using netifaces
array_interfaces_ip = []
network_interfaces = netifaces.interfaces()

for interface in network_interfaces:
    try:
        ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        array_interfaces_ip.append(ip)
    except KeyError:
        pass

for local_ip in array_interfaces_ip:
    parameters.append({'LOCAL_IP': local_ip})
    metadata.append({'local_ip': local_ip})

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_local_ip",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCAL_IP']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_local_ip_valid(get_configuration, configure_environment, restart_remoted):
    """Check if the `local_ip` option could be configured using different valid IPs without errors.

    Check if the API answer for manager connection coincides with the option selected on `ossec.conf`.

    Raises:
        AssertionError: if API answer is different of expected configuration.
    """
    cfg = get_configuration['metadata']

    # Check that API query return the selected configuration
    compare_config_api_response([cfg], 'remote')
