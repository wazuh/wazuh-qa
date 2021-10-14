# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_basic.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)

daemons_handler_configuration = {'daemons': ['wazuh-logcollector']}

local_internal_options = {'logcollector.debug': 2,
                          'logcollector.sample_log_length': 200}

macos_log_messages = [
    {
        'command': 'os_log',
        'type': 'log',
        'level': 'error',
        'subsystem': 'testing.wazuh-agent.macos',
        'category': 'category',
        'id': 'os_log_command'
    },
    {
        'command': 'logger',
        'message': 'Logger message example',
        'id': 'logger_command'
    }
]

macos_log_message_timeout = 40
macos_monitoring_macos_log_timeout = 30

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def up_wazuh_after_module():

    yield
    control_service('restart')

@pytest.fixture(scope="function")
def restart_logcollector_function():
    control_service('restart', 'wazuh-logcollector')



@pytest.mark.parametrize('macos_message', macos_log_messages,
                         ids=[log_message['id'] for log_message in macos_log_messages])
def test_macos_format_basic(get_configuration, configure_environment, configure_local_internal_options_module,
                            macos_message, file_monitoring, daemons_handler, up_wazuh_after_module,
                            restart_logcollector_function):

    """Check if logcollector gather correctly macOS unified logging system events.

    This test uses logger tool and a custom log to generate ULS events. The agent is connected to a authd simulator
    and sended events are gather using remoted simulator tool.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    expected_macos_message = ""
    log_command = macos_message['command']

    log_monitor.start(timeout=macos_monitoring_macos_log_timeout, callback=logcollector.callback_monitoring_macos_logs,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    time.sleep(3)

    if log_command == 'logger':
        logcollector.generate_macos_logger_log(macos_message['message'])
        expected_macos_message = logcollector.format_macos_message_pattern(macos_message['command'],
                                                                           macos_message['message'])

    elif log_command == 'os_log':
        logcollector.generate_macos_custom_log(macos_message['type'], macos_message['level'],
                                               macos_message['subsystem'], macos_message['category'])
        expected_macos_message = logcollector.format_macos_message_pattern(
                                                'custom_log', logcollector.TEMPLATE_OSLOG_MESSAGE,
                                                subsystem=macos_message['subsystem'],
                                                category=macos_message['category'])

    log_monitor.start(timeout=macos_log_message_timeout, callback=logcollector.callback_macos_log(expected_macos_message),
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)
