'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check that specified 'denied-ips' connection is denied and
       syslog produces a 'not allowed' message.

components:
    - remoted

suite: configuration

targets:
    - manager

daemons:
    - wazuh-remoted

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-remoted.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html
    - https://documentation.wazuh.com/current/user-manual/agents/agent-life-cycle.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/agent-key-polling.html

tags:
    - remoted
'''
import os
import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

import wazuh_testing.remote as remote
import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.utils import format_ipv6_long
from urllib3.exceptions import InsecureRequestWarning
import requests

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


def test_denied_ips_syslog(get_configuration, configure_environment, restart_remoted, wait_for_remoted_start_log):
    '''
    description: Check that 'wazuh-remoted' denied connection to the specified 'denied-ips'.
                 For this purpose, it uses the configuration from test cases, check if the different errors are
                 logged correctly and check if the API retrieves the expected configuration.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration.
        - restart_remoted:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that remoted starts correctly.
        - Verify that the warning is logged correctly in ossec.log when receives a message from blocked ip.
        - Verify that the error is logged correctly in ossec.log when receives a message from blocked ip.
        - Verify that the critical error is logged correctly in ossec.log when receives a message from blocked ip.
        - Verify that the API query matches correctly with the configuration that ossec.conf contains.
        - Verify that the selected configuration is the same as the API response.

    input_description: A configuration template (test_basic_configuration_allowed_denied_ips) is contained in an
                       external YAML file, (wazuh_basic_configuration.yaml). That template is combined with different
                       test cases defined in the module. Those include configuration settings for the 'wazuh-remoted'
                       daemon and agents info.

    expected_output:
        - r'Started <pid>: .* Listening on port .*'
        - Wazuh remoted did not start as expected.
        - r'Remote syslog allowed from: .*'
        - The expected output for denied-ips has not been produced.
        - r'Message from .* not allowed. Cannot find the ID of the agent'
        - r'API query '{protocol}://{host}:{port}/manager/configuration?section=remote' doesn't match the
          introduced configuration on ossec.conf.'

    tags:
        - remoted
    '''
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
