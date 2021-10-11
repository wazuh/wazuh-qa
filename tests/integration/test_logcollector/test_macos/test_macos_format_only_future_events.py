# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import fnmatch
import os

import pytest
from wazuh_testing import logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_format_only_future_events.yaml')
parameters = [{'ONLY_FUTURE_EVENTS': 'yes'}, {'ONLY_FUTURE_EVENTS': 'no'}]
metadata = [{'only-future-events': 'yes'}, {'only-future-events': 'no'}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['ONLY_FUTURE_EVENTS']}" for x in parameters]


daemons_handler_configuration = {'daemons': ['wazuh-logcollector'], 'all_daemons': True}

local_internal_options = {'logcollector.debug': 2,
                          'logcollector.sample_log_length': 100}

macos_log_message_timeout = 40
macos_monitoring_macos_log_timeout = 30

# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


def test_macos_format_only_future_events(get_configuration, configure_environment, 
                                         configure_local_internal_options_module,
                                         daemons_handler, file_monitoring):
    """Check if logcollector use correctly only-future-events option using macos log format.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    log_monitor = FileMonitor(LOG_FILE_PATH)

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    only_future_events = get_configuration['metadata']['only-future-events']

    old_message = 'Old logger message'
    new_message = 'New logger message'

    logcollector.generate_macos_logger_log(old_message)
    expected_old_macos_message = logcollector.format_macos_message_pattern('logger', old_message)


    log_monitor.start(timeout=macos_log_message_timeout, 
                              callback=logcollector.callback_macos_log(expected_old_macos_message))

    ## Stop wazuh agent and ensure it gets old macos messages if only-future-events option is disabled

    control_service('stop', 'wazuh-logcollector')

    truncate_file(LOG_FILE_PATH)
    log_monitor = FileMonitor(LOG_FILE_PATH)

    control_service('start', 'wazuh-logcollector')


    log_monitor.start(timeout=macos_monitoring_macos_log_timeout, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    if only_future_events == 'yes':
        with pytest.raises(TimeoutError):
            log_monitor.start(timeout=macos_log_message_timeout, callback=logcollector.callback_macos_log(expected_old_macos_message))

    else:
            log_monitor.start(timeout=macos_log_message_timeout, callback=logcollector.callback_macos_log(expected_old_macos_message))

    logcollector.generate_macos_logger_log(new_message)

    expected_new_macos_message = logcollector.format_macos_message_pattern('logger', new_message)
    log_monitor.start(timeout=macos_log_message_timeout, callback=logcollector.callback_macos_log(expected_new_macos_message),
                error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)
