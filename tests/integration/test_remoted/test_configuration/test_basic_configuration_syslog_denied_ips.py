# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.remote as remote
import wazuh_testing.api as api

from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
configurations_path = os.path.join(test_data_path, 'data', 'wazuh_basic_configuration.yaml')

parameters = [
    {'ALLOWED': '127.0.0.0/24', 'DENIED': '127.0.0.1'}
]

metadata = [
    {'allowed-ips': '127.0.0.0/24', 'denied-ips': '127.0.0.1'}
]

configurations = load_wazuh_configurations(configurations_path, 'test_basic_configuration_allowed_denied_ips' , params=parameters, metadata=metadata)
configuration_ids = [f"{x['ALLOWED']}_{x['DENIED']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_denied_ips_syslog(get_configuration, configure_environment, restart_remoted):
    """Check that `wazuh-remoted` block messages from `denied-ips`.

    Check if the API answer for manager connection coincides with the option selected on `ossec.conf`.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected error message or API answer different
        of expected configuration.
    """
    cfg = get_configuration['metadata']

    log_callback = remote.callback_detect_syslog_allowed_ips(cfg['allowed-ips'])

    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="Wazuh remoted didn't start as expected.")

    remote.send_syslog_message(message='Feb 22 13:08:48 Remoted Syslog Denied testing', port=514, protocol=remote.UDP)

    log_callback = remote.callback_detect_syslog_denied_ips(cfg['denied-ips'])

    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected output for denied-ips has not been produced")

    # Check that API query return the selected configuration
    api.compare_config_api_response(cfg, 'remote')
