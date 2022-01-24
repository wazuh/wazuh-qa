# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

import wazuh_testing.remote as remote
import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.utils import format_ipv6_long

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
configurations_path = os.path.join(test_data_path, 'data', 'wazuh_basic_configuration.yaml')

parameters = [
    {'ALLOWED': '127.0.0.0/24', 'DENIED': '127.0.0.1', 'IPV6': 'no'},
    {'ALLOWED': '0000:0000:0000:0000:0000:0000:0000:0001/64', 'DENIED': '::1', 'IPV6': 'yes'},
    {'ALLOWED': '::1/64', 'DENIED': '::1', 'IPV6': 'yes'}
]

metadata = [
    {'allowed-ips': '127.0.0.0/24', 'denied-ips': '127.0.0.1', 'ipv6': 'no'},
    {'allowed-ips': '0000:0000:0000:0000:0000:0000:0000:0001/64', 'denied-ips': '::1', 'ipv6': 'yes'},
    {'allowed-ips': '::1/64', 'denied-ips': '::1', 'ipv6': 'yes'}
]

configurations = load_wazuh_configurations(configurations_path, 'test_basic_configuration_allowed_denied_ips',
                                           params=parameters, metadata=metadata)
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
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    cfg = get_configuration['metadata']

    allowed_ips = cfg['allowed-ips'].split('/')
    denied_ip = cfg['denied-ips']
    if cfg['ipv6'] == 'yes':
        denied_ip = format_ipv6_long(denied_ip)

    if len(allowed_ips) > 1:
        allowed_ips_mask = allowed_ips[1]
        allowed_ips_address = allowed_ips[0]

        expected_allowed_ips_address = allowed_ips_address
        if cfg['ipv6'] == 'yes':
            expected_allowed_ips_address = format_ipv6_long(allowed_ips_address)
        expected_allowed_ips = expected_allowed_ips_address + '/' + allowed_ips_mask

    else:
        expected_allowed_ips = allowed_ips

    log_callback = remote.callback_detect_syslog_allowed_ips(expected_allowed_ips)

    wazuh_log_monitor.start(timeout=remote.REMOTED_GLOBAL_TIMEOUT, callback=log_callback,
                            error_message="Wazuh remoted didn't start as expected.")

    remote.send_syslog_message(message='Feb 22 13:08:48 Remoted Syslog Denied testing', port=514, protocol=remote.UDP,
                               manager_address=denied_ip)

    log_callback = remote.callback_detect_syslog_denied_ips(denied_ip)

    wazuh_log_monitor.start(timeout=remote.REMOTED_GLOBAL_TIMEOUT, callback=log_callback,
                            error_message="The expected output for denied-ips has not been produced")

    # Check that API query return the selected configuration
    api.compare_config_api_response([cfg], 'remote')
