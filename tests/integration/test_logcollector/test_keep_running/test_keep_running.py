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

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_keep_running_conf.yaml')
temp_dir = tempfile.gettempdir()
log_test_path = os.path.join(temp_dir, 'test_log.log')

local_internal_options = {
    'logcollector.debug': 2,
    'monitord.rotate_log': 0,
    'logcollector.vcheck_files': 5
}

parameters = [
    {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path}
]
metadata = [
    {'log_format': 'syslog', 'location': log_test_path,
     'log_line_before': "DEBUG: Reading syslog message: 'BEFORE'",
     'log_line_after': "DEBUG: Reading syslog message: 'AFTER'"}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"rotate_{x['location']}_in_{x['log_format']}_format" for x in metadata]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get internal configuration."""
    return local_internal_options


@pytest.fixture(scope="module")
def generate_log_file():
    """Generate a log file for testing."""
    file.write_file(log_test_path, '')
    yield
    file.remove_file(log_test_path)


def test_keep_running(get_local_internal_options, configure_local_internal_options, get_configuration,
                      configure_environment, generate_log_file, restart_logcollector):
    """Check if logcollector keeps running once a log is rotated.

    To do this, logcollector is configured to monitor a log file, then data is added to the log and it is rotated.
    Finally, write data back to the rotated log and check that logcollector continues to monitor it.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration for testing.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        generate_log_file (fixture): Generate a log file for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.
    """
    config = get_configuration['metadata']

    # Add first line to log
    message = config['log_line_before']
    with open(config['location'], 'a') as f:
        f.write(f"{message}\n")

    # Ensure that the file is being analyzed
    message = fr"INFO: \(\d*\): Analyzing file: '{log_test_path}'."
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=monitoring.make_callback(pattern=message,
                                                              prefix=LOG_COLLECTOR_DETECTOR_PREFIX,
                                                              escape=False))

    # Add another line to log
    message = config['log_line_before']
    with open(config['location'], 'a') as f:
        f.write(f"{message}\n")

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=monitoring.make_callback(pattern=message,
                                                              prefix=LOG_COLLECTOR_DETECTOR_PREFIX,
                                                              escape=False))

    file.truncate_file(config['location'])

    # Ensure that the rotation has been completed:
    message = f"DEBUG: File size reduced. {log_test_path}"
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=monitoring.make_callback(pattern=message,
                                                              prefix=LOG_COLLECTOR_DETECTOR_PREFIX,
                                                              escape=False))
    # Add first line to rotated log
    message = config['log_line_after']
    with open(config['location'], 'a') as f:
        f.write(f"{message}\n")

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=monitoring.make_callback(pattern=message,
                                                              prefix=LOG_COLLECTOR_DETECTOR_PREFIX,
                                                              escape=False))
