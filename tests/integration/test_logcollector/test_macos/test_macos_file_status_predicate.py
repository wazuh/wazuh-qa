# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import re

# from wazuh_testing.logcollector import DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION
from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH, LOG_FILE_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.tools.monitoring import FileMonitor, wait_file, make_callback
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.logcollector import prefix as logcollector_prefix
from wazuh_testing.tools.file import read_json, truncate_file

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_file_status_predicate.yaml')

parameters = [{'ONLY_FUTURE_EVENTS': 'yes'}, {'ONLY_FUTURE_EVENTS': 'no'}]
metadata = [{'only-future-events': 'yes'}, {'only-future-events': 'no'}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['ONLY_FUTURE_EVENTS']}" for x in parameters]

daemons_handler_configuration = {'daemons': ['wazuh-logcollector'], 'ignore_errors': False}

# Max number of characters to be displayed in the log's debug message
sample_log_length = 100
# Time in seconds to update the file_status.json
file_status_update_time = 4

local_internal_options = { 'logcollector.vcheck_files': file_status_update_time,
                           'logcollector.sample_log_length': sample_log_length }

# Maximum waiting time in seconds to find the logs on ossec.log
file_monitor_timeout = 30

wazuh_log_monitor = None


# Fixtures
@pytest.fixture(scope='module')
def startup_cleanup():
    """Truncate ossec.log and remove logcollector's file_status.json file."""
    truncate_file(WAZUH_LOCAL_INTERNAL_OPTIONS)
    truncate_file(LOG_FILE_PATH)
    os.remove(LOGCOLLECTOR_FILE_STATUS_PATH) if os.path.exists(LOGCOLLECTOR_FILE_STATUS_PATH) else None


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def callback_log_bad_predicate():
    """Check if 'line' has the macOS ULS bad predicate message on it."""
    return make_callback(pattern="Execution error 'log:", prefix=logcollector_prefix)


def callback_log_exit_log():
    """Check if 'line' has the macOS ULS log stream exited message on it."""
    return make_callback(pattern="macOS 'log stream' process exited, pid:", prefix=logcollector_prefix)


def test_macos_file_status_predicate(startup_cleanup,
                                     configure_local_internal_options_module,
                                     get_configuration,
                                     configure_environment,
                                     daemons_handler):
    """Checks that logcollector does not store 'macos'-formatted localfile data since its predicate is erroneous.

    The agent is connected to the authd simulator and uses a dummy localfile (/Library/Ossec/logs/active-responses.log)
    which triggers the creation of file_status.json

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
        FileNotFoundError: If the file_status.json is not available in the expected time.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    wazuh_log_monitor.start(timeout=file_monitor_timeout,
                            callback=callback_log_bad_predicate(),
                            error_message='Expected log that matches the regex '
                                          '".*Execution error \'log:" could not be found')

    wazuh_log_monitor.start(timeout=file_monitor_timeout,
                            callback=callback_log_exit_log(),
                            error_message='Expected log that matches the regex '
                                          '".*macOS \'log stream\' process exited, pid:" could not be found')

    # Waiting for file_status.json to be created, with a timeout about the time needed to update the file
    wait_file(LOGCOLLECTOR_FILE_STATUS_PATH, file_monitor_timeout)

    file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)

    # Check if json has a structure
    if 'macos' in file_status_json:
        assert False, 'Error, "macos" key should not be present on the status file'
