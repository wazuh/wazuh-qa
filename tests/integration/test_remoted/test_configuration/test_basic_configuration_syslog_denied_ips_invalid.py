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
configurations_path = os.path.join(test_data_path, 'wazuh_test_active_response.yaml')

parameters = [
    {'ALLOWED': '127.0.0.0', 'DENIED': '192.168.1.1.1'},
    {'ALLOWED': '127.0.0.0', 'DENIED': 'Testing'},
    {'ALLOWED': '127.0.0.0', 'DENIED': '192.168.1.1/7890'}
]

metadata = [
    {'allowed-ips': '127.0.0.0', 'denied-ips': '192.168.1.1.1'},
    {'allowed-ips': '127.0.0.0', 'denied-ips': 'Testing'},
    {'allowed-ips': '127.0.0.0', 'denied-ips': '192.168.1.1/7890'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_allowed_denied_ips",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['ALLOWED']}_{x['DENIED']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_denied_ips_syslog_invalid(get_configuration, configure_environment, restart_remoted):
    """Test if `wazuh-remoted` fails when invalid `denied-ips` label value is set.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected error message.
    """
    cfg = get_configuration['metadata']

    log_callback = remote.callback_error_invalid_ip(cfg['denied-ips'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = remote.callback_error_in_configuration('ERROR')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = remote.callback_error_in_configuration('CRITICAL')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
