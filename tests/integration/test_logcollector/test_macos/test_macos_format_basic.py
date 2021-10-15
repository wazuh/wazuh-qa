# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.remote import check_agent_received_message
# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_basic.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)

macos_log_messages = [
    {
        'command': 'os_log',
        'type': 'log',
        'level': 'error',
        'subsystem': 'testing.wazuh-agent.macos',
        'category': 'category',
        'id': 'example'
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


@pytest.mark.parametrize('macos_message', macos_log_messages,
                         ids=[log_message['id'] for log_message in macos_log_messages])
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

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    wazuh_log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    if log_command == 'logger':
        logcollector.generate_macos_logger_log(macos_message['message'])
        expected_macos_message = logcollector.format_macos_message_pattern(macos_message['command'],
                                                                           macos_message['message'])

    elif log_command == 'os_log':
        logcollector.generate_macos_custom_log(macos_message['type'],macos_message['level'], macos_message['subsystem'],
                                               macos_message['category'])
        expected_macos_message = logcollector.format_macos_message_pattern(
                                                'custom_log',
                                                logcollector.TEMPLATE_OSLOG_MESSAGE, 'log', macos_message['subsystem'],
                                                macos_message['category'])

    check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_macos_message, timeout=40)
