'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, these tests will check the agent-manager communication with different protocols.
       Two threads are using, one for sending the message and other for monitoring the queue socket.

components:
    - remoted

suite: agent_communication

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html
    - https://documentation.wazuh.com/current/user-manual/agents/agent-life-cycle.html

tags:
    - remoted
'''
import pytest
import os

from time import sleep
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools import file
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import remote as rd

# Marks
pytestmark = pytest.mark.tier(level=0)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_protocols_communication.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Set configuration
parameters = [
    {'PROTOCOL': 'tcp', 'PORT': 1514},
    {'PROTOCOL': 'udp', 'PORT': 1514},
    {'PROTOCOL': 'tcp,udp', 'PORT': 1514},
    {'PROTOCOL': 'udp,tcp', 'PORT': 1514},
    {'PROTOCOL': 'tcp', 'PORT': 56000},
    {'PROTOCOL': 'udp', 'PORT': 56000},
    {'PROTOCOL': 'tcp,udp', 'PORT': 56000},
    {'PROTOCOL': 'udp,tcp', 'PORT': 56000},
]

metadata = [
    {'protocol': 'tcp', 'port': 1514},
    {'protocol': 'udp', 'port': 1514},
    {'protocol': 'tcp,udp', 'port': 1514},
    {'protocol': 'udp,tcp', 'port': 1514},
    {'protocol': 'tcp', 'port': 56000},
    {'protocol': 'udp', 'port': 56000},
    {'protocol': 'tcp,udp', 'port': 56000},
    {'protocol': 'udp,tcp', 'port': 56000},
]

agent_info = {
    'server_address': '127.0.0.1',
    'os': 'debian7',
    'version': '4.2.0',
    'disable_all_modules': True
}

configuration_ids = [f"{item['PROTOCOL'].upper()}_{item['PORT']}" for item in parameters]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def validate_agent_manager_protocol_communication(protocol, manager_port):
    """Allow to validate if the agent-manager communication using a certain protocol has been successfull.

    For this purpose, two jobs are launched concurrently. One for monitoring the queue socket and other for sending the
    message.

    Args:
        protocol (str): Message sending protocol. It can be TCP or UDP.
        manager_port (int): Manager port when remoted is listening.

    Raises:
        TimeoutError: If the expected event could not be found in queue socket.
    """
    file.truncate_file(LOG_FILE_PATH)

    socket_monitor_thread = ThreadExecutor(rd.check_queue_socket_event)

    send_message_thread = ThreadExecutor(rd.send_agent_event, {'wazuh_log_monitor': wazuh_log_monitor,
                                                               'protocol': protocol, 'manager_port': manager_port})
    # Start log monitoring
    socket_monitor_thread.start()

    # Time to wait until starting the log monitoring
    sleep(5)

    # Send agent message
    send_message_thread.start()

    # Wait until the threads end
    socket_monitor_thread.join()
    _, sender = send_message_thread.join()

    # Close socket connection
    sender.socket.close()


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_protocols_communication(get_configuration, configure_environment, restart_remoted):
    '''
    description: Check agent-manager communication via TCP, UDP or both.
                 For this purpose, the test will log and send the message to check if the communication works fine.
                 Then, after the sender ends, the socket connection is closed.
    
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
        - Verify that the agent sends correctly a message to the manager using a specific protocol and port.
    
    input_description: A configuration template (test_protocols_communication) is contained in an external YAML file,
                       (wazuh_protocols_communication.yaml). That template is combined with different test cases defined
                       in the module. Those include configuration settings for the 'wazuh-remoted' daemon and agents
                       info.
                        
    expected_output:
        - r'.* Accepted publickey for root from 192.168.0.5 port 48044 .*'
        - The expected event could not be found in queue socket
    
    tags:
        - simulator
        - remoted
    '''
    protocol = get_configuration['metadata']['protocol']
    manager_port = get_configuration['metadata']['port']

    if protocol in ['udp,tcp', 'tcp,udp']:
        validate_agent_manager_protocol_communication(rd.TCP, manager_port)
        validate_agent_manager_protocol_communication(rd.UDP, manager_port)
    else:
        validate_agent_manager_protocol_communication(protocol, manager_port)
