'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check if 'wazuh-remoted' can receive syslog messages through
       the socket.

components:
    - remoted

suite: socket_communication

targets:
    - manager

daemons:
    - wazuh-remoted

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-remoted.html

tags:
    - remoted
'''
import os

import pytest
import wazuh_testing.remote as remote
from wazuh_testing import is_udp
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_syslog.yaml')

syslog_messages = {
    'dummy': "Syslog message sent by wazuh-qa to test remoted syslog",
    'failed_login_sshd': remote.EXAMPLE_INVALID_USER_LOG_EVENT,
    'failed_login_sshd_pri_header': f"<1>{remote.EXAMPLE_INVALID_USER_LOG_EVENT}",
    'multi_log_failed_login_sshd_logon_success':
        f"{remote.EXAMPLE_INVALID_USER_LOG_EVENT}\n{remote.EXAMPLE_VALID_USER_LOG_EVENT}",
    'multi_log_failed_login_sshd_logon_success_pri_header':
        f"<1>{remote.EXAMPLE_INVALID_USER_LOG_EVENT}\n<2>{remote.EXAMPLE_VALID_USER_LOG_EVENT}",
    'multi_log_failed_login_sshd_logon_success_pri_header_mix_with_without':
        f"<1>{remote.EXAMPLE_INVALID_USER_LOG_EVENT}\n{remote.EXAMPLE_VALID_USER_LOG_EVENT}",
    'multi_log_failed_login_sshd_logon_success_pri_header_mix_without_with':
        f"{remote.EXAMPLE_INVALID_USER_LOG_EVENT}\n{remote.EXAMPLE_VALID_USER_LOG_EVENT}",
    'dummy_pri_header': f"<dummy>{remote.EXAMPLE_INVALID_USER_LOG_EVENT}",
    'dummy_bad_formatted_pri_header': f"<dummy_header{remote.EXAMPLE_INVALID_USER_LOG_EVENT}"
}

parameters = [
    {'PROTOCOL': 'UDP', 'PORT': 514},
    {'PROTOCOL': 'UDP', 'PORT': 51000},
    {'PROTOCOL': 'TCP', 'PORT': 514},
    {'PROTOCOL': 'TCP', 'PORT': 51000},
    {'PROTOCOL': 'udp', 'PORT': 514},
    {'PROTOCOL': 'udp', 'PORT': 51000},
    {'PROTOCOL': 'tcp', 'PORT': 514},
    {'PROTOCOL': 'tcp', 'PORT': 51000}
]

metadata = [
    {'protocol': 'UDP', 'port': 514},
    {'protocol': 'UDP', 'port': 51000},
    {'protocol': 'TCP', 'port': 514},
    {'protocol': 'TCP', 'port': 51000},
    {'protocol': 'udp', 'port': 514},
    {'protocol': 'udp', 'port': 51000},
    {'protocol': 'tcp', 'port': 514},
    {'protocol': 'tcp', 'port': 51000}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"syslog_{x['PROTOCOL']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize("message", syslog_messages.keys())
def test_syslog_message(message, get_configuration, configure_environment, restart_wazuh):
    '''
    description: Check if 'wazuh-remoted' can receive syslog messages through the socket.
    
    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - message:
            type: fixture
            brief: Message sent
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_remoted:
            type: fixture
            brief: Restart 'wazuh-remoted' daemon in manager.
    
    assertions:
        - Verify the syslog message is received.
    
    input_description: A configuration template (test_syslog_message) is contained in an external YAML file,
                       (wazuh_syslog.yaml). That template is combined with different test cases defined
                       in the module. Those include configuration settings for the 'wazuh-remoted' daemon
                       and agents info.
    
    expected_output:
        - r'Started <pid>: .* Listening on port .*'
        - r'<.>.*'
    '''
    config = get_configuration['metadata']
    port, protocol = config['port'], config['protocol']

    if is_udp(protocol) and '\n' in syslog_messages[message]:
        pytest.skip('UDP only supports one message per datagram.')

    # Monitor the archives.log
    wazuh_archives_log_monitor = remote.create_archives_log_monitor()

    # Check if remoted correctly started with the new conf
    log_callback = remote.callback_detect_remoted_started(port=port, protocol=protocol, connection_type='syslog')
    wazuh_log_monitor.start(timeout=5, callback=log_callback, update_position=False,
                            error_message="Wazuh remoted didn't start as expected.")

    # Check if wazuh-remoted receives syslog messages
    remote.check_syslog_event(wazuh_archives_log_monitor, syslog_messages[message], port, protocol)
