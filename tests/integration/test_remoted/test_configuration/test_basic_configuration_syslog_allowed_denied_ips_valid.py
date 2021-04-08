# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.remote as remote
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'ALLOWED': '127.0.0.0/24', 'DENIED': '192.168.1.1/24'},
    {'ALLOWED': '127.0.0.0/25', 'DENIED': '192.168.1.1/25'},
    {'ALLOWED': '127.0.0.0/26', 'DENIED': '192.168.1.1/26'},
    {'ALLOWED': '127.0.0.0/27', 'DENIED': '192.168.1.1/27'},
    {'ALLOWED': '127.0.0.0/30', 'DENIED': '192.168.1.1/30'}
]

metadata = [
    {'allowed-ips': '127.0.0.0/24', 'denied-ips': '192.168.1.1/24'},
    {'allowed-ips': '127.0.0.0/25', 'denied-ips': '192.168.1.1/25'},
    {'allowed-ips': '127.0.0.0/26', 'denied-ips': '192.168.1.1/26'},
    {'allowed-ips': '127.0.0.0/27', 'denied-ips': '192.168.1.1/27'},
    {'allowed-ips': '127.0.0.0/30', 'denied-ips': '192.168.1.1/30'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_allowed_denied_ips",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['ALLOWED']}_{x['DENIED']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_allowed_denied_ips_syslog(get_configuration, configure_environment, restart_remoted):
    """Check that "allowed-ips" and "denied-ips" could be configured without errors for syslog connection.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `wazuh.log` expected error message.
    """
    cfg = get_configuration['metadata']

    log_callback = remote.callback_detect_syslog_allowed_ips(cfg['allowed-ips'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="Wazuh remoted didn't start as expected.")

    remote.compare_config_api_response(cfg)
