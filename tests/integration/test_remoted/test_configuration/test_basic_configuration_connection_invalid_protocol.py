'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check that in case a protocol is invalid only the valid one
       is used. In addition, if none protocol is valid, TCP should be used.

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
from wazuh_testing.api import compare_config_api_response

from wazuh_testing.tools.configuration import load_wazuh_configurations
from urllib3.exceptions import InsecureRequestWarning
import requests

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'PROTOCOL': 'Testing,UDP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'Testing,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,UDP,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'Testing,UDP', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP,Testing', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'Testing,Testing', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP,UDP,Testing', 'CONNECTION': 'syslog', 'PORT': '514'}
]
metadata = [
    {'protocol': 'Testing,UDP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'Testing,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,UDP,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'Testing,UDP', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP,Testing', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'Testing,Testing', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP,UDP,Testing', 'connection': 'syslog', 'port': '514'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_protocol(get_configuration, configure_environment, restart_remoted, wait_for_remoted_start_log):
    '''
    description: Check if 'wazuh-remoted' sets properly prococol values.
                 First of all, it selects a valid protocol to be used. If a pair of protocols is provided, in case one
                 of them is invalid, it should be used the valid protocol. Otherwise, if none of them is valid, TCP
                 should be used(For a syslog connection if more than one protocol is provided only TCP should be used).
                 For this purpose, it selects a valid protocol(within a proper checking), checks if remoted is properly
                 started and if the configuration is the same as the API reponse.

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
        - Verify that invalid procotol selection warning message appears in ossec.log.
        - Verify that no valid protocol selection warning message appears in ossec.log.
        - Verify that remoted starts correctly.
        - Verify that the selected configuration is the same that API response.

    input_description: A configuration template (test_basic_configuration_connection) is contained in an external YAML
                       file, (wazuh_basic_configuration.yaml). That template is combined with different test cases
                       defined in the module. Those include configuration settings for the 'wazuh-remoted' daemon and
                       agents info.

    expected_output:
        - The expected error output has not been produced
        - r'WARNING: .* Ignored invalid value .* for protocol field.'
        - r'WARNING: .* Error getting protocol. Default value TCP will be used.'
        - r'Started <pid>: .* Listening on port .*'

    tags:
        - simulator
    '''
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    cfg = get_configuration['metadata']
    protocol_field = cfg['protocol'].split(',')

    valid_invalid_protocols = remote.get_protocols(protocol_field)

    valid_protocol = valid_invalid_protocols[0]
    invalid_protocol_list = valid_invalid_protocols[1]

    for invalid_protocol in invalid_protocol_list:
        log_callback = remote.callback_ignored_invalid_protocol(invalid_protocol)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    if len(valid_protocol) == 0:
        log_callback = remote.callback_error_getting_protocol()
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    elif len(valid_protocol) == 1:
        log_callback = remote.callback_detect_remoted_started(cfg['port'], valid_protocol[0], cfg['connection'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    else:
        used_protocol = 'TCP,UDP'
        if cfg['connection'] == 'syslog':
            used_protocol = 'TCP'
        log_callback = remote.callback_detect_remoted_started(cfg['port'], used_protocol, cfg['connection'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    real_configuration = cfg.copy()
    real_configuration['protocol'] = cfg['protocol'].split(',')

    # Check that API query return the selected configuration
    compare_config_api_response([real_configuration], 'remote')
