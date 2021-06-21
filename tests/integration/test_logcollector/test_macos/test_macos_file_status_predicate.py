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

macos_log_messages = [
    {
        'command': 'logger',
        'message': "Logger testing message - file status",
    }
]

file_status_update = 4

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


def extra_configuration_before_yield():
    """Delete old OFE data and change file status update interval."""
    # Remove old data from json_status
    os.remove(file_status_path) if os.path.exists(file_status_path) else None
    # Set default values
    change_internal_options('logcollector.vcheck_files', str(file_status_update))

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


@pytest.mark.parametrize('macos_message', macos_log_messages)
def test_macos_file_status_predicate(get_configuration, configure_environment, get_connection_configuration,
                                 init_authd_remote_simulator, macos_message, restart_logcollector):

    """Checks if logcollector stores correctly "macos"-formatted localfile data.

    This test uses logger tool and a custom log to generate an ULS event. The agent is connected to the authd simulator
    and sends an event to trigger the file_status.json update.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callback_log_bad_predicate,
                            error_message="log 1: ")

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callback_log_exit_log,
                            error_message="log 2: ")
    
    file_status_json = ""

    # Waiting for file_status.json to be updated with macOS data by logcollector
    time.sleep(file_status_update + 5)

    try:
        with open(file_status_path) as json_status:
            file_status_json = json.loads(json_status.read())
    except EnvironmentError:
        assert False, "Error opening '{}'".format(file_status_path)

    # Check if json has a structure
    assert file_status_json["macos"], "Error finding 'macos' key"

