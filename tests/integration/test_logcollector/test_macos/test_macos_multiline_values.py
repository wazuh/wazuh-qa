# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_basic.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)
local_internal_options = {'logcollector.debug': 2,
                          'logcollector.sample_log_length': 200}

daemons_handler_configuration = {'daemons': ['wazuh-logcollector']}

macos_log_messages = [
    {
        'command': 'logger',
        'message': "Here is a multiline log. Line 0 \nLine 1. \nLast line.",
    }
]

macos_uls_time_to_wait_after_start = 3
macos_logcollector_start = 30

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
def test_macos_multiline_values(get_configuration, configure_environment,
                                macos_message, daemons_handler, file_monitoring):

    """Check if logcollector correctly collects multiline events from the macOS unified logging system.

    This test uses logger tool and a custom log to generate ULS events. The agent is connected to a authd simulator
    and sended events are gather using remoted simulator tool.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=macos_logcollector_start, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)
    time.sleep(macos_uls_time_to_wait_after_start)

    multiline_message = macos_message['message'].split('\n')
    multiline_logger = f"\"$(printf \"{macos_message['message']}\")\""
    logcollector.generate_macos_logger_log(multiline_logger)

    for line in multiline_message:
        log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT,
                          callback=logcollector.callback_read_macos_message(line),
                          error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)
