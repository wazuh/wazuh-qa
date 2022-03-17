'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check if 'wazuh-remoted' sends the #pong message.

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

import wazuh_testing.remote as rm
from wazuh_testing import TCP_UDP
from wazuh_testing.tools.configuration import load_wazuh_configurations


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_socket_communication.yaml')

parameters = [
    {'PROTOCOL': 'UDP', 'PORT': 1514},
    {'PROTOCOL': 'UDP', 'PORT': 56000},
    {'PROTOCOL': 'TCP', 'PORT': 1514},
    {'PROTOCOL': 'TCP', 'PORT': 56000},
    {'PROTOCOL': 'UDP,TCP', 'PORT': 1514},
    {'PROTOCOL': 'UDP,TCP', 'PORT': 56000},
    {'PROTOCOL': 'TCP,UDP', 'PORT': 1514},
    {'PROTOCOL': 'TCP,UDP', 'PORT': 56000},
    {'PROTOCOL': 'TCP,TCP', 'PORT': 1514},
    {'PROTOCOL': 'UDP,UDP', 'PORT': 1514},
    {'PROTOCOL': 'TCP,TCP', 'PORT': 56000},
    {'PROTOCOL': 'UDP,UDP', 'PORT': 56000},
    {'PROTOCOL': 'udp', 'PORT': 1514},
    {'PROTOCOL': 'udp', 'PORT': 56000},
    {'PROTOCOL': 'tcp', 'PORT': 1514},
    {'PROTOCOL': 'tcp', 'PORT': 56000},
    {'PROTOCOL': 'udp,tcp', 'PORT': 1514},
    {'PROTOCOL': 'udp,tcp', 'PORT': 56000},
    {'PROTOCOL': 'tcp,udp', 'PORT': 1514},
    {'PROTOCOL': 'tcp,udp', 'PORT': 56000},
    {'PROTOCOL': 'tcp,tcp', 'PORT': 1514},
    {'PROTOCOL': 'udp,udp', 'PORT': 1514},
    {'PROTOCOL': 'tcp,tcp', 'PORT': 56000},
    {'PROTOCOL': 'udp,udp', 'PORT': 56000},
]

metadata = [
    {'protocol': 'UDP', 'port': 1514},
    {'protocol': 'UDP', 'port': 56000},
    {'protocol': 'TCP', 'port': 1514},
    {'protocol': 'TCP', 'port': 56000},
    {'protocol': 'UDP,TCP', 'port': 1514},
    {'protocol': 'UDP,TCP', 'port': 56000},
    {'protocol': 'TCP,UDP', 'port': 1514},
    {'protocol': 'TCP,UDP', 'port': 56000},
    {'protocol': 'TCP,TCP', 'port': 1514},
    {'protocol': 'UDP,UDP', 'port': 1514},
    {'protocol': 'TCP,TCP', 'port': 56000},
    {'protocol': 'UDP,UDP', 'port': 56000},
    {'protocol': 'udp', 'port': 1514},
    {'protocol': 'udp', 'port': 56000},
    {'protocol': 'tcp', 'port': 1514},
    {'protocol': 'tcp', 'port': 56000},
    {'protocol': 'udp,tcp', 'port': 1514},
    {'protocol': 'udp,tcp', 'port': 56000},
    {'protocol': 'tcp,udp', 'port': 1514},
    {'protocol': 'tcp,udp', 'port': 56000},
    {'protocol': 'tcp,tcp', 'port': 1514},
    {'protocol': 'udp,udp', 'port': 1514},
    {'protocol': 'tcp,tcp', 'port': 56000},
    {'protocol': 'udp,udp', 'port': 56000},
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_ping_pong_message(get_configuration, configure_environment, restart_remoted):
    '''
    description: Check if 'wazuh-remoted' sends the #pong message
    
    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
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
        - Verify the #pong message is sent correctly.
    
    input_description: A configuration template (test_ping_pong_message) is contained in an external YAML file,
                       (wazuh_socket_communication.yaml). That template is combined with different test cases defined
                       in the module. Those include configuration settings for the 'wazuh-remoted' daemon
                       and agents info.
    
    expected_output:
        - r'Started <pid>: .* Listening on port .*'
    '''
    config = get_configuration['metadata']

    test_multiple_pings = False

    if config['protocol'] in ['TCP,UDP', 'UDP,TCP', 'tcp,udp', 'udp,tcp']:
        protocol, test_multiple_pings = TCP_UDP, True
    elif config['protocol'] in ['TCP,TCP', 'UDP,UDP', 'tcp,tcp', 'udp,udp']:
        protocol = config['protocol'].split(',')[0]
    else:
        protocol = config['protocol']

    log_callback = rm.callback_detect_remoted_started(port=config['port'], protocol=protocol)

    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="Wazuh remoted didn't start as expected.")

    if test_multiple_pings:
        assert b'#pong' == rm.send_ping_pong_messages(manager_address="localhost", protocol=rm.UDP, port=config['port'])
        assert b'#pong' == rm.send_ping_pong_messages(manager_address="localhost", protocol=rm.TCP, port=config['port'])
    else:
        assert b'#pong' == rm.send_ping_pong_messages(manager_address="localhost", protocol=protocol,
                                                      port=config['port'])

