# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import tempfile

import pytest
import wazuh_testing.logcollector as logcollector
from wazuh_testing import global_parameters
from wazuh_testing.tools import monitoring, file
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# Configuration
DAEMON_NAME = "wazuh-logcollector"
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_only_future_events_conf.yaml')
temp_dir = tempfile.gettempdir()
log_test_path = os.path.join(temp_dir, 'wazuh-testing', 'test.log')
current_line = 0

local_internal_options = {'logcollector.vcheck_files': 5}

parameters = [
    {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'ONLY_FUTURE_EVENTS': 'no', 'MAX_SIZE': '10MB'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'ONLY_FUTURE_EVENTS': 'yes', 'MAX_SIZE': '10MB'}
]
metadata = [
    {'log_format': 'syslog', 'location': log_test_path, 'only_future_events': 'no',
     'log_line': "Jan  1 00:00:00 localhost test[0]: line="},
    {'log_format': 'syslog', 'location': log_test_path, 'only_future_events': 'yes',
     'log_line': "Jan  1 00:00:00 localhost test[0]: line="}
]

log_line = metadata[0]['log_line']

file_structure = [
    {
        'folder_path': os.path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.log'],
        'content': log_line,
        'size_kib': 10240
    }
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"rotate_{x['location']}_in_{x['log_format']}_format" for x in metadata]


#Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get internal configuration."""
    return local_internal_options


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


def test_only_future_events(get_local_internal_options, configure_local_internal_options, get_configuration,
                            configure_environment, get_files_list, create_file_structure_module, restart_logcollector):
    """Check if the "only-future-events" option is working correctly.

    To do this, logcollector is stopped and several lines are added to a test log file.
    Depending on the value of the "only-future-events" option the following should happen:
    If the value is "yes" the added lines should not be detected, on the other hand,
    if the value is "no" those lines should be detected by logcollector.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration for testing.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        generate_log_file (fixture): Generate a log file for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.
    """
    config = get_configuration['metadata']
    global current_line

    # Ensure that the file is being analyzed
    message = fr"INFO: \(\d*\): Analyzing file: '{log_test_path}'."
    callback_message = monitoring.make_callback(pattern=message, prefix=LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Add one KiB of data to log
    current_line = logcollector.add_log_data(log_path=config['location'], log_line_message=config['log_line'],
                                             size_kib=1, line_start=current_line + 1, print_line_num=True)

    message = f"DEBUG: Reading syslog message: '{config['log_line']}{current_line}'"
    callback_message = monitoring.make_callback(pattern=message, prefix=LOG_COLLECTOR_DETECTOR_PREFIX, escape=True)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    control_service('stop', daemon=DAEMON_NAME)

    # Add another KiB of data to log while logcollector is stopped
    first_line = current_line + 1
    current_line = logcollector.add_log_data(log_path=config['location'], log_line_message=config['log_line'],
                                             size_kib=1, line_start=first_line, print_line_num=True)

    control_service('start', daemon=DAEMON_NAME)

    if config['only_future_events'] == 'no':
        # Logcollector should detect the first line written while it was stopped
        # Check first line
        message = f"DEBUG: Reading syslog message: '{config['log_line']}{first_line}'"
        callback_message = monitoring.make_callback(pattern=message, prefix=LOG_COLLECTOR_DETECTOR_PREFIX, escape=True)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                                callback=callback_message)
        # Check last line
        message = f"DEBUG: Reading syslog message: '{config['log_line']}{current_line}'"
        callback_message = monitoring.make_callback(pattern=message, prefix=LOG_COLLECTOR_DETECTOR_PREFIX, escape=True)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                                callback=callback_message)
    else:
        # Logcollector should NOT detect the log lines written while it was stopped
        with pytest.raises(TimeoutError):
            # Check first line
            message = f"DEBUG: Reading syslog message: '{config['log_line']}{first_line}'"
            callback_message = monitoring.make_callback(pattern=message, prefix=LOG_COLLECTOR_DETECTOR_PREFIX,
                                                        escape=True)
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                                    callback=callback_message)
            # Check last line
            message = f"DEBUG: Reading syslog message: '{config['log_line']}{current_line}'"
            callback_message = monitoring.make_callback(pattern=message, prefix=LOG_COLLECTOR_DETECTOR_PREFIX,
                                                        escape=True)
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                                    callback=callback_message)

    # Add another KiB of data to log (additional check)
    current_line = logcollector.add_log_data(log_path=config['location'], log_line_message=config['log_line'],
                                             size_kib=1, line_start=current_line + 1, print_line_num=True)

    message = f"DEBUG: Reading syslog message: '{config['log_line']}{current_line}'"
    callback_message = monitoring.make_callback(pattern=message, prefix=LOG_COLLECTOR_DETECTOR_PREFIX, escape=True)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)
