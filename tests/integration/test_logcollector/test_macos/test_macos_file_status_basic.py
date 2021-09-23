# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import pytest
import wazuh_testing.logcollector as logcollector

from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, wait_file
from wazuh_testing.tools.file import read_json, truncate_file

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_file_status_basic.yaml')

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

macos_message = {   'command': 'logger',
                    'message': 'Logger testing message - file status'   }

# Maximum waiting time in seconds to find the logs on ossec.log
file_monitor_timeout = 30

wazuh_log_monitor = None

expected_message = logcollector.format_macos_message_pattern(macos_message['command'], macos_message['message'])


# Fixtures
@pytest.fixture(scope='module')
def startup_cleanup():
    """Truncate ossec.log and remove logcollector's file_status.json file."""
    truncate_file(LOG_FILE_PATH)
    os.remove(LOGCOLLECTOR_FILE_STATUS_PATH) if os.path.exists(LOGCOLLECTOR_FILE_STATUS_PATH) else None

@pytest.fixture(scope='module')
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def wait_macos_uls_log(line):
    """Callback function to wait for the macOS' ULS log collected by logcollector."""
    if re.search(expected_message, line):
        return True

    return None


def wait_logcollector_log_stream(line):
    """Check if 'line' has the logcollector's macOS ULS module start message."""
    if re.search(r'Monitoring macOS logs with: (.+?)log stream', line):
        return True

    return None

def wait_macos_key_file_status(line):
    """Check if 'line' has the 'macos' key on it."""
    if re.search(r'macos', line):
        return True

    return None


def test_macos_file_status_basic(startup_cleanup,
                                 configure_local_internal_options, 
                                 get_configuration,
                                 configure_environment,
                                 daemons_handler):
    """Checks if logcollector stores correctly "macos"-formatted localfile data.

    This test uses logger tool and a custom log to generate an ULS event. The agent is connected to the authd simulator
    and sends an event to trigger the file_status.json update.

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
        FileNotFoundError: If the file_status.json is not available in the expected time.
    """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    wazuh_log_monitor.start(timeout=file_monitor_timeout,
                            callback=logcollector.callback_monitoring_macos_logs,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    # Watches the ossec.log to check when logcollector starts the macOS ULS module
    wazuh_log_monitor.start(timeout=file_monitor_timeout,
                            callback=wait_logcollector_log_stream,
                            error_message='Logcollector did not start')

    logcollector.generate_macos_logger_log(macos_message['message'])

    wazuh_log_monitor.start(timeout=file_monitor_timeout,
                            callback=wait_macos_uls_log,
                            error_message='MacOS ULS log was not found')

    # Waits for file_status.json to be created, with a timeout about the time needed to update the file
    wait_file(LOGCOLLECTOR_FILE_STATUS_PATH, file_monitor_timeout)

    # Watches the file_status.json file for the "macos" key
    file_status_monitor = FileMonitor(LOGCOLLECTOR_FILE_STATUS_PATH)
    file_status_monitor.start(timeout=file_monitor_timeout,
                            callback=wait_macos_key_file_status,
                            error_message="The 'macos' key could not be found on the file_status.json file")

    file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)

    conf_predicate = get_configuration['sections'][0]['elements'][2]['query']['value']
    conf_level = get_configuration['sections'][0]['elements'][2]['query']['attributes'][0]['level']
    conf_type = get_configuration['sections'][0]['elements'][2]['query']['attributes'][1]['type']

    # Check if json has a structure
    assert file_status_json['macos'], "Error finding 'macos' key"

    assert file_status_json['macos']['timestamp'], "Error finding 'timestamp' key inside 'macos'"

    assert re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}-\d{4}$',
                    file_status_json['macos']['timestamp']), \
                    'Error of timestamp format'

    assert file_status_json['macos']['settings'], "Error finding 'settings' key inside 'macos'"

    assert file_status_json['macos']['settings'] \
                        == logcollector.compose_macos_log_command(conf_type,
                                                                conf_level,
                                                                conf_predicate)
