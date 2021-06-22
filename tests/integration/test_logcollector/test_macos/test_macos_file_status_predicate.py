# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import json
import re
import time
import wazuh_testing.logcollector as logcollector
from wazuh_testing.fim import change_internal_options
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing import global_parameters
from wazuh_testing.tools.monitoring import FileMonitor

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

file_status_path = os.path.join(WAZUH_PATH, 'queue', 'logcollector', 'file_status.json')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Maximum waiting time in seconds to find the logs on ossec.log
wazuh_log_monitor_timeout = 30

# Time in seconds to update the file_status.json
file_status_update = 4

local_internal_options = {'logcollector.vcheck_files': str(file_status_update)}
@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options

def extra_configuration_before_yield():
    """Delete file status file."""
    os.remove(file_status_path) if os.path.exists(file_status_path) else None

def callback_log_bad_predicate(line):
    match = re.match(r'.*Execution error \'log:', line)
    if match:
        return True
    return None

def callback_log_exit_log(line):
    match = re.match(r'.*macOS \'log stream\' process exited, pid:', line)
    if match:
        return True
    return None

# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


def test_macos_file_status_predicate(get_local_internal_options, get_configuration, configure_environment, 
                                     get_connection_configuration, init_authd_remote_simulator, restart_logcollector):

    """Checks that logcollector does not store "macos"-formatted localfile data since its predicate is erroneous.

    The agent is connected to the authd simulator and uses a dummy localfile (/Library/Ossec/logs/active-responses.log) 
    which triggers the creation of file_status.json

    Raises:
        TimeoutError: If the expected callbacks are not satisfied.
    """

    wazuh_log_monitor.start(timeout=wazuh_log_monitor_timeout,
                            callback=callback_log_bad_predicate,
                            error_message="Expected log that matches the regex "
                                          "'.*Execution error \'log:' could not be found")

    wazuh_log_monitor.start(timeout=wazuh_log_monitor_timeout,
                            callback=callback_log_exit_log,
                            error_message="Expected log that matches the regex "
                                          "'.*macOS \'log stream\' process exited, pid:' could not be found")

    file_status_json = ""

    # Waiting for file_status.json tocat be updated with macOS data by logcollector
    time.sleep(file_status_update + 1)

    try:
        with open(file_status_path) as json_status:
            file_status_json = json.loads(json_status.read())
    except EnvironmentError:
        assert False, "Error opening '{}'".format(file_status_path)

    # Check if json has a structure
    if "macos" in file_status_json:
        assert False, "Error, macos should not be present on the status file"
