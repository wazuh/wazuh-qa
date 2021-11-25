# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import wazuh_testing.logcollector as logcollector

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.logcollector import LOG_COLLECTOR_GLOBAL_TIMEOUT
from wazuh_testing.tools.monitoring import FileMonitor, wait_file
from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH
from wazuh_testing.tools.file import read_json
from os.path import dirname, join, realpath
from re import match


# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = join(dirname(realpath(__file__)), 'data')
configurations_path = join(test_data_path, 'wazuh_macos_file_status_basic.yaml')

parameters = [{'ONLY_FUTURE_EVENTS': 'yes'}, {'ONLY_FUTURE_EVENTS': 'no'}]
metadata = [{'only-future-events': 'yes'}, {'only-future-events': 'no'}]

daemons_handler_configuration = {'daemons': ['wazuh-logcollector'], 'ignore_errors': False}

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"only_future_events_{x['ONLY_FUTURE_EVENTS']}" for x in parameters]

# Max number of characters to be displayed in the log's debug message
sample_log_length = 100
# Time in seconds to update the file_status.json
file_status_update_time = 4

local_internal_options = {'logcollector.debug': 2,
                          'logcollector.vcheck_files': file_status_update_time,
                          'logcollector.sample_log_length': sample_log_length}

macos_message = {'command': 'logger',
                 'message': 'Logger testing message - file status'}

# Expected message to be used on the "callback_macos_uls_log" callback
expected_message = logcollector.format_macos_message_pattern(macos_message['command'], macos_message['message'])


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_macos_file_status_basic(restart_logcollector_required_daemons_package, truncate_log_file, delete_file_status_json,
                                 configure_local_internal_options_module,
                                 get_configuration, configure_environment,
                                 file_monitoring, daemons_handler):
    """Checks if logcollector stores correctly "macos"-formatted localfile data.

    This test uses logger tool and a custom log to generate an ULS event. When logcollector receives a valid log, then
    the file_status.json is updated.

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
        FileNotFoundError: If the file_status.json is not available in the expected time.
    """
    log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT,
                      callback=logcollector.callback_monitoring_macos_logs,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    # Watches the ossec.log to check when logcollector starts the macOS ULS module
    log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT,
                      callback=logcollector.callback_logcollector_log_stream_log(),
                      error_message='Logcollector did not start.')

    logcollector.generate_macos_logger_log(macos_message['message'])

    log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT,
                      callback=logcollector.callback_macos_uls_log(expected_message),
                      error_message="MacOS ULS log was not found: '{}'.".format(expected_message))

    # Waits for file_status.json to be created, with a timeout about the time needed to update the file
    wait_file(LOGCOLLECTOR_FILE_STATUS_PATH, LOG_COLLECTOR_GLOBAL_TIMEOUT)

    # Watches the file_status.json file for the "macos" key
    file_status_monitor = FileMonitor(LOGCOLLECTOR_FILE_STATUS_PATH)

    file_status_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT,
                              callback=logcollector.callback_file_status_macos_key(),
                              error_message="The 'macos' key could not be found on the file_status.json file")

    file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)

    conf_predicate = get_configuration['sections'][0]['elements'][2]['query']['value']
    conf_level = get_configuration['sections'][0]['elements'][2]['query']['attributes'][0]['level']
    conf_type = get_configuration['sections'][0]['elements'][2]['query']['attributes'][1]['type']

    # Check if json has a structure
    assert file_status_json['macos'], "Error finding 'macos' key"

    assert file_status_json['macos']['timestamp'], "Error finding 'timestamp' key inside 'macos'"

    assert match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[-+]\d{4}$', file_status_json['macos']['timestamp']), \
        'Error of timestamp format'

    assert file_status_json['macos']['settings'], "Error finding 'settings' key inside 'macos'"

    assert file_status_json['macos']['settings'] \
        == logcollector.compose_macos_log_command(conf_type, conf_level, conf_predicate)