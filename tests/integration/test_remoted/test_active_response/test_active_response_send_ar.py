'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Active responses perform various countermeasures to address active
       threats, such as blocking access to an agent from the threat source when certain
       criteria are met. These tests will check if an active response command is sent
       correctly to the Wazuh agent by `wazuh-remoted` daemon.

components:
    - remoted

suite: active_response

targets:
    - manager

daemons:
    - wazuh-remoted
    - wazuh-execd

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html

tags:
    - remoted
    - active_response
'''
import os
import pytest
import time

import wazuh_testing.remote as remote
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import UDP, TCP, TCP_UDP
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.sockets import send_active_response_message

# Marks
pytestmark = pytest.mark.tier(level=1)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_test_active_response.yaml')

parameters = [
    {'PROTOCOL': TCP, 'PORT': '1514'},
    {'PROTOCOL': UDP, 'PORT': '1514'},
    {'PROTOCOL': TCP_UDP, 'PORT': '1514'},
    {'PROTOCOL': TCP, 'PORT': '4565'},
    {'PROTOCOL': UDP, 'PORT': '4565'},
    {'PROTOCOL': TCP_UDP, 'PORT': '4565'}

]
metadata = [
    {'protocol': TCP, 'port': '1514'},
    {'protocol': UDP, 'port': '1514'},
    {'protocol': TCP_UDP, 'port': '1514'},
    {'protocol': TCP, 'port': '4565'},
    {'protocol': UDP, 'port': '4565'},
    {'protocol': TCP_UDP, 'port': '4565'}
]

configurations = load_wazuh_configurations(configurations_path, __name__ ,
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['PORT']}" for x in parameters]

manager_address = 'localhost'


# fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skip(reason="It requires review and a rework for the agent simulator."
                         "Sometimes it doesn't work properly when it sends keepalives "
                         "messages causing the agent to never being in active status.")
def test_active_response_ar_sending(get_configuration, configure_environment, restart_remoted):
    '''
    description: Check if the 'wazuh-remoted' daemon sends active response commands to the Wazuh agent.
                 For this purpose, the test will establish a connection with a simulated agent using
                 different ports and transport protocols. Then, it will send an active response to that
                 agent, and finally, the test will verify that the events indicating that the active
                 response has been sent by the manager and received it by the agent are generated.
    
    wazuh_min_version: 4.2.0
    
    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_remoted:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
    
    assertions:
        - Verify that the 'wazuh-execd' daemon sends the active response to the 'wazuh-remoted' daemon.
        - Verify that the 'wazuh-remoted' daemon receives the active response from the 'wazuh-execd' daemon.
        - Verify that the Wazuh agent receives an active response message.
    
    input_description: A configuration template (test_active_response_send_ar) is contained in an external YAML
                       file (wazuh_test_active_response.yaml). That template is combined with different
                       test cases defined in the module. Those include configuration settings for
                       the 'wazuh-remoted' daemon.
    
    expected_output:
        - r'.*Active response request received.*'
        - r'.*Active response sent.*'
    
    tags:
        - active_response
        - simulator
    '''
    protocol_array = (get_configuration['metadata']['protocol']).split(',')
    manager_port = get_configuration['metadata']['port']

    for protocol in protocol_array:
        # rcv_msg_limit of 1000 is necessary for UDP test
        agent = ag.Agent(manager_address, 'aes', os='debian8', version='4.2.0',
                         disable_all_modules=True, rcv_msg_limit=1000)
        agent.set_module_status('receive_messages', 'enabled')
        agent.set_module_status('keepalive', 'enabled')

        # Time necessary until socket creation
        time.sleep(10)

        sender, injector = ag.connect(agent, manager_address, protocol, manager_port)

        try:
            active_response_message = f"(local_source) [] NRN {agent.id} {remote.ACTIVE_RESPONSE_EXAMPLE_COMMAND}"

            send_active_response_message(active_response_message)

            log_callback = remote.callback_active_response_received(active_response_message)
            wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                    error_message='The expected event has not been found in ossec.log')

            log_callback = remote.callback_active_response_sent(active_response_message)

            wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                    error_message='The expected event has not been found in ossec.log')

            remote.check_agent_received_message(agent, f"#!-execd {remote.ACTIVE_RESPONSE_EXAMPLE_COMMAND}", escape=True)
        finally:
            injector.stop_receive()
