# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import fnmatch
import os

import pytest
from wazuh_testing import logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.remote import check_agent_received_message
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=1)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_only_future_events.yaml')
parameters = [{'ONLY_FUTURE_EVENTS': 'yes'}, {'ONLY_FUTURE_EVENTS': 'no'}]
metadata = [{'only-future-events': 'yes'}, {'only-future-events': 'no'}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['ONLY_FUTURE_EVENTS']}" for x in parameters]


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


def test_macos_format_only_future_events(get_configuration, configure_environment, get_connection_configuration,
                                         init_authd_remote_simulator, restart_logcollector):
    """Check if logcollector use correctly only-future-events option using macos log format.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    wazuh_log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    only_future_events = get_configuration['metadata']['only-future-events']

    old_message = 'Old logger message'
    new_message = 'New logger message'

    logcollector.macos_logger_message(old_message)
    expected_old_macos_message = logcollector.format_macos_message_pattern('logger', old_message)
    check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_old_macos_message, timeout=40)

    ## Stop wazuh agent and ensure it gets old macos messages if only-future-events option is disabled

    control_service('restart')


    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs

    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    wazuh_log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    if only_future_events:
        with pytest.raises(TimeoutError):
            check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_old_macos_message, timeout=40)

    else:
        check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_old_macos_message, timeout=40)

    logcollector.macos_logger_message(new_message)

    expected_new_macos_message = logcollector.format_macos_message_pattern('logger', new_message)

    check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_new_macos_message, timeout=40)
