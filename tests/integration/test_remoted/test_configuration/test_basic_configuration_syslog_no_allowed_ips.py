'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check that 'wazuh-remoted' fails when syslog connection is used
       but there aren't any 'allowed-ips' specified.

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

import wazuh_testing.remote as remote
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'CONNECTION': 'syslog', 'IPV6': 'no'},
    {'CONNECTION': 'syslog', 'IPV6': 'yes'}
]
metadata = [
    {'connection': 'syslog', 'ipv6': 'no'},
    {'connection': 'syslog', 'ipv6': 'yes'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['CONNECTION']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_allowed_denied_ips_syslog(get_configuration, configure_environment, restart_remoted):
    '''
    description: Check that 'wazuh-remoted' fails when 'allowed-ips' is not provided but syslog connection is used.
                 For this purpose, it uses the configuration from test cases, and check that fail info message has been
                 logged in 'ossec.log'.
    
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
        - Verify that the error is logged when it tries to connect without configure allowed-ips field.
    
    input_description: A configuration template (test_basic_configuration_syslog_no_allowed_ipsww) is contained in an
                       external YAML file, (wazuh_basic_configuration.yaml). That template is combined with different
                       test cases defined in the module. Those include configuration settings for the 'wazuh-remoted'
                       daemon and agents info.
    
    expected_output:
        - r'Started <pid>: .* Listening on port .*'
        - The expected error output has not been produced.
        - r'INFO: .* IP or network must be present in syslog access list <allowed-ips>.'
    
    tags:
        - remoted
    '''
    log_callback = remote.callback_info_no_allowed_ips()
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
