# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from time import sleep
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.remote import check_agent_received_message

# Marks
pytestmark = pytest.mark.tier(level=1)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_basic.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)

macos_log_messages = [
    {
        'command': 'logger',
        'message': "Logger testing message",
    },
    {
        'command': 'os_log',
        'type': 'error',
        'subsystem': 'testing.wazuh-agent.macos',
        'category': 'category',
        'message': 1,
    }
]


# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


@pytest.mark.parametrize('macos_message', macos_log_messages)
def test_macos_format_basic(get_configuration, configure_environment, get_connection_configuration,
                            init_authd_remote_simulator, macos_message, restart_logcollector):

    """Check if logcollector gather correctly macOS unified logging system events.

    This test uses logger tool and a custom log to generate ULS events. The agent is connected to a authd simulator
    and sended events are gather using remoted simulator tool.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    expected_macos_message = ""
    log_command = macos_message['command']

    if log_command == 'logger':
        logcollector.macos_logger_message(macos_message['message'])
        expected_macos_message = logcollector.format_macos_message_pattern(macos_message['command'],
                                                                           macos_message['message'])

    elif log_command == 'os_log':
        logcollector.macos_os_log_message(macos_message['type'], macos_message['subsystem'], macos_message['category'])
        expected_macos_message = logcollector.format_macos_message_pattern(
                                                        'custom_log',
                                                        logcollector.TEMPLATE_OSLOG_MESSAGE, macos_message['subsystem'],
                                                        macos_message['category'])
        
    check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_macos_message, timeout=20)
