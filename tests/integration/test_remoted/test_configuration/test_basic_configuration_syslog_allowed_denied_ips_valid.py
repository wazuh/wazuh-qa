# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import ipaddress

import wazuh_testing.remote as remote
from wazuh_testing.api import compare_config_api_response

from wazuh_testing.tools.configuration import load_wazuh_configurations
from urllib3.exceptions import InsecureRequestWarning
import requests

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters_single = [
    {'ALLOWED': '127.0.0.0/24', 'DENIED': '192.168.1.1/24', 'IPV6': 'no'},
    {'ALLOWED': '0000:0000:0000:0000:0000:0000:0000:0001/64', 'DENIED': 'fe80::1003:889f:a584:0101/64', 'IPV6': 'yes'},
    {'ALLOWED': '::1/64', 'DENIED': 'fe80::1003:889f:a584:0101/64', 'IPV6': 'yes'}
]

metadata_single = [
    {'allowed-ips': '127.0.0.0/24', 'denied-ips': '192.168.1.1/24', 'ipv6': 'no'},
    {'allowed-ips': '0000:0000:0000:0000:0000:0000:0000:0001/64', 'denied-ips': 'fe80::1003:889f:a584:0101/64',
     'ipv6': 'yes'},
    {'allowed-ips': '::1/64', 'denied-ips': 'fe80::1003:889f:a584:0101/64', 'ipv6': 'yes'}
]

parameters_multiple = [
    {'ALLOWED': '127.0.0.0/24', 'ALLOWED2': '192.168.0.0/24', 'DENIED': '192.168.1.1/24', 'IPV6': 'no'},
    {'ALLOWED': '0000:0000:0000:0000:0000:0000:0000:0001/64',
        'ALLOWED2': '0000:0000:0000:0000:0000:0000:0000:0002/64', 'DENIED': 'fe80::1003:889f:a584:0101/64',
        'IPV6': 'yes'},
    {'ALLOWED': '::1/64', 'ALLOWED2': '::2/64', 'DENIED': 'fe80::1003:889f:a584:0101/64', 'IPV6': 'yes'},
    {'ALLOWED': '127.0.0.0/24', 'ALLOWED2': '0000:0000:0000:0000:0000:0000:0000:0001/64', 'DENIED': '192.168.1.1/24',
     'IPV6': 'yes'},
    {'ALLOWED': '127.0.0.0/24', 'ALLOWED2': '::1/64', 'DENIED': '192.168.1.1/24', 'IPV6': 'yes'},
    {'ALLOWED': '::1/64', 'ALLOWED2': '0000:0000:0000:0000:0000:0000:0000:0002/64', 'DENIED': '192.168.1.1/24',
     'IPV6': 'yes'}
]

metadata_multiple = [
    {'allowed-ips': '127.0.0.0/24', 'allowed-ips2': '192.168.0.0/24', 'denied-ips': '192.168.1.1/24', 'ipv6': 'no'},
    {'allowed-ips': '0000:0000:0000:0000:0000:0000:0000:0001/64',
        'allowed-ips2': '0000:0000:0000:0000:0000:0000:0000:0002/64', 'denied-ips': 'fe80::1003:889f:a584:0101/64',
        'ipv6': 'yes'},
    {'allowed-ips': '::1/64', 'allowed-ips2': '::2/64', 'denied-ips': 'fe80::1003:889f:a584:0101/64', 'ipv6': 'yes'},
    {'allowed-ips': '127.0.0.0/24',
        'allowed-ips2': '0000:0000:0000:0000:0000:0000:0000:0001/64', 'denied-ips': '192.168.1.1/24', 'ipv6': 'yes'},
    {'allowed-ips': '127.0.0.0/24', 'allowed-ips2': '::1/64', 'denied-ips': '192.168.1.1/24', 'ipv6': 'yes'},
    {'allowed-ips': '::1/64',
        'allowed-ips2': '0000:0000:0000:0000:0000:0000:0000:0002/64', 'denied-ips': '192.168.1.1/24', 'ipv6': 'yes'}
]

parameters = parameters_single + parameters_multiple
metadata = metadata_single + metadata_multiple

configurations_single = load_wazuh_configurations(configurations_path, "test_basic_configuration_allowed_denied_ips",
                                                  params=parameters_single, metadata=metadata_single)
configurations_multiple = load_wazuh_configurations(configurations_path,
                                                    "test_basic_configuration_multiple_allowed_denied_ips",
                                                    params=parameters_multiple, metadata=metadata_multiple)
configurations = configurations_single + configurations_multiple
configuration_ids = []
for x in parameters:
    if 'ALLOWED2' not in x:
        configuration_ids.append(f"{x['ALLOWED']}_{x['DENIED']}_{x['IPV6']}")
    else:
        configuration_ids.append(f"{x['ALLOWED']}_{x['ALLOWED2']}_{x['DENIED']}_{x['IPV6']}")


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_allowed_denied_ips_syslog(get_configuration, configure_environment, restart_remoted):
    """Check that "allowed-ips" and "denied-ips" could be configured without errors for syslog connection.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected error message.
    """
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    cfg = get_configuration['metadata']

    address = cfg['allowed-ips'][:-3]
    netmask = cfg['allowed-ips'][-3:]
    allowed_ips = ipaddress.ip_address(address).exploded + netmask
    log_callback = remote.callback_detect_syslog_allowed_ips(allowed_ips)
    wazuh_log_monitor.start(timeout=remote.REMOTED_GLOBAL_TIMEOUT, callback=log_callback,
                            error_message="Wazuh remoted didn't start as expected.")

    if 'allowed-ips2' in cfg:
        pytest.xfail(f"Expected error: https://github.com/wazuh/wazuh/issues/11643")
        address2 = cfg['allowed-ips2'][:-3]
        netmask2 = cfg['allowed-ips2'][-3:]
        allowed_ips2 = ipaddress.ip_address(address2).exploded + netmask2
        log_callback = remote.callback_detect_syslog_allowed_ips(allowed_ips2)
        wazuh_log_monitor.start(timeout=remote.REMOTED_GLOBAL_TIMEOUT, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

        cfg['allowed-ips'] = [cfg['allowed-ips'], cfg['allowed-ips2']]
        cfg.pop('allowed-ips2')

    compare_config_api_response([cfg], 'remote')
