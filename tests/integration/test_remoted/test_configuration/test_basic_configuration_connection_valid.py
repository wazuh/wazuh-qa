'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check that 'connection' can be configured as 'secure' or 'syslog'
       properly.

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
    {'PROTOCOL': 'UDP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'UDP', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP', 'CONNECTION': 'syslog', 'PORT': '553'},
    {'PROTOCOL': 'TCP', 'CONNECTION': 'secure', 'PORT': '23467'},
    {'PROTOCOL': 'TCP,UDP', 'CONNECTION': 'secure', 'PORT': '1209'},
    {'PROTOCOL': 'TCP,UDP', 'CONNECTION': 'syslog', 'PORT': '2134'},
    {'PROTOCOL': 'UDP,TCP', 'CONNECTION': 'secure', 'PORT': '55632'},
    {'PROTOCOL': 'UDP,TCP', 'CONNECTION': 'syslog', 'PORT': '2134'}
]
metadata = [
    {'protocol': 'UDP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'UDP', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP', 'connection': 'syslog', 'port': '553'},
    {'protocol': 'TCP', 'connection': 'secure', 'port': '23467'},
    {'protocol': 'TCP,UDP', 'connection': 'secure', 'port': '1209'},
    {'protocol': 'TCP,UDP', 'connection': 'syslog', 'port': '2134'},
    {'protocol': 'UDP,TCP', 'connection': 'secure', 'port': '55632'},
    {'protocol': 'UDP,TCP', 'connection': 'syslog', 'port': '2134'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_connection_valid(get_configuration, configure_environment, restart_remoted, wait_for_remoted_start_log):
    '''
    description: Check if 'wazuh-remoted' sets 'connection' as 'secure' or 'syslog' properly.
                 For this purpose, it loads the configuration from test cases cfg(For a syslog connection if more than
                 one protocol is provided, only TCP should be used), checks if remoted is properly started and if the
                 configuration is the same as the API reponse.

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
        - Verify that a proper protocol is used.
        - Verify that invalid procotol selection warning message appears in ossec.log.
        - Verify that remoted starts correctly.
        - Verify that the selected configuration is the same that API response.

    input_description: A configuration template (test_basic_configuration_connection) is contained in an external YAML
                       file, (wazuh_basic_configuration.yaml). That template is combined with different test cases
                       defined in the module. Those include configuration settings for the 'wazuh-remoted' daemon and
                       agents info.

    expected_output:
        - The expected error output has not been produced
        - r'WARNING: .* Only secure connection supports TCP and UDP at the same time.'
        - Default value TCP will be used.
        - r'Started <pid>: .* Listening on port .*'

    tags:
        - simulator
    '''
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    cfg = get_configuration['metadata']

    used_protocol = cfg['protocol']

    if (cfg['protocol'] == 'TCP,UDP' or cfg['protocol'] == 'UDP,TCP') and cfg['connection'] == 'syslog':
        log_callback = remote.callback_warning_syslog_tcp_udp()
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

        used_protocol = 'TCP'

    log_callback = remote.callback_detect_remoted_started(cfg['port'], used_protocol, cfg['connection'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    real_configuration = cfg.copy()
    real_configuration['protocol'] = cfg['protocol'].split(',')
    compare_config_api_response([real_configuration], 'remote')
