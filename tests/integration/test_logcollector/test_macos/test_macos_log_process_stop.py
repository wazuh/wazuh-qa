# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import platform

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import search_process, control_service
from time import sleep

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_basic.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_macos_log_process_stop(get_configuration, configure_environment, restart_logcollector):
    """Check if logcollector stops log process when Wazuh agent stops.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """

    macos_sierra = True if str(platform.mac_ver()[0]).startswith('10.12') else False

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    wazuh_log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    process_to_stop = ['log']
    if macos_sierra:
        process_to_stop += ['script']

    for process in process_to_stop:
        log_processes = search_process(process)
        assert len(log_processes) == 1

    control_service('stop', daemon='wazuh-logcollector')

    sleep(5)

    for process in process_to_stop:
        log_processes = search_process(process)
        assert len(log_processes) == 0

    control_service('start', daemon='wazuh-logcollector')

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    wazuh_log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    for process in process_to_stop:
        log_processes = search_process(process)
        assert len(log_processes) == 1

    control_service('stop')

    sleep(5)

    for process in process_to_stop:
        log_processes = search_process(process)
        assert len(log_processes) == 0

    control_service('start')
