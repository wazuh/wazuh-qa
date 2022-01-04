# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import sys
import time

from wazuh_testing.logcollector import (LOG_COLLECTOR_GLOBAL_TIMEOUT,
                                        callback_log_macos_stream_exit,
                                        callback_log_bad_predicate)
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import wait_file
from wazuh_testing.tools.file import read_json
from os.path import dirname, join, realpath
if sys.platform != 'win32':
    from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = join(dirname(realpath(__file__)), 'data')
configurations_path = join(test_data_path, 'wazuh_macos_file_status_predicate.yaml')

parameters = [{'ONLY_FUTURE_EVENTS': 'yes'}, {'ONLY_FUTURE_EVENTS': 'no'}]
metadata = [{'only-future-events': 'yes'}, {'only-future-events': 'no'}]

daemons_handler_configuration = {'daemons': ['wazuh-logcollector'], 'ignore_errors': False}

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"only_future_events_{x['ONLY_FUTURE_EVENTS']}" for x in parameters]

# Time in seconds to update the file_status.json
file_status_update_time = 4

local_internal_options = {'logcollector.vcheck_files': file_status_update_time}


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skip(reason="Unexpected false positive, further investigation is required")
def test_macos_file_status_predicate(restart_logcollector_required_daemons_package, truncate_log_file,
                                     delete_file_status_json,
                                     configure_local_internal_options_module,
                                     get_configuration, configure_environment,
                                     file_monitoring, daemons_handler):
    """Checks that logcollector does not store 'macos'-formatted localfile data since its predicate is erroneous.

    The agent uses a dummy localfile (/Library/Ossec/logs/active-responses.log) which triggers the creation of
    file_status.json file.

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
        FileNotFoundError: If the file_status.json is not available in the expected time.
    """
    time.sleep(2)
    log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT,
                      callback=callback_log_bad_predicate(),
                      error_message='Expected log that matches the regex ".*Execution error \'log:" could not be found')

    log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT,
                      callback=callback_log_macos_stream_exit(),
                      error_message='Expected log that matches the regex '
                                    '".*macOS \'log stream\' process exited, pid:" could not be found')

    # Waiting for file_status.json to be created, with a timeout about the time needed to update the file
    wait_file(LOGCOLLECTOR_FILE_STATUS_PATH, LOG_COLLECTOR_GLOBAL_TIMEOUT)

    file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)

    # Check if json has a structure
    if 'macos' in file_status_json:
        assert False, 'Error, "macos" key should not be present on the status file'
