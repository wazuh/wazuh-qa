# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.logcollector import LOG_COLLECTOR_GLOBAL_TIMEOUT, callback_logcollector_started
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_json, write_json_file
from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH
from wazuh_testing.tools.monitoring import wait_file
from os.path import dirname, join, exists, realpath
from tempfile import gettempdir
from time import sleep
from os import remove

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = join(dirname(realpath(__file__)), 'data')
configurations_path = join(test_data_path, 'wazuh_macos_file_status_when_no_macos.yaml')

dummy_file = join(gettempdir(), 'dummy_file.log')
parameters = [{'FILE_TO_MONITOR': dummy_file}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters)

daemons_handler_configuration = {'daemons': ['wazuh-logcollector'],
                                 'ignore_errors': False}

# Time in seconds to update the file_status.json
file_status_update_time = 4

local_internal_options = {'logcollector.vcheck_files': file_status_update_time}

# Time to wait for file_status.json to be updated (the +8 is due to a delay added by the wazuh-agentd daemmon)
wait_file_status_update_time = file_status_update_time + 8


# Fixtures
@pytest.fixture(scope='module')
def handle_files():
    """Create dummy file to be monitored by logcollector, after the test it is deleted."""
    with open(dummy_file, 'w') as f:
        pass

    yield

    remove(dummy_file) if exists(dummy_file) else None


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_macos_file_status_when_no_macos(restart_logcollector_required_daemons_package, truncate_log_file, handle_files,
                                         delete_file_status_json,
                                         configure_local_internal_options_module,
                                         get_configuration,
                                         configure_environment,
                                         file_monitoring, daemons_handler):
    """Checks that logcollector does not store and removes, if exists, previous "macos"-formatted localfile data in the
    file_status.json

    Given a file_status.json that contains a valid combination of "settings" and "timestamp" of "macos", when starting
    an agent that has no "macos" localfile configured on its ossec.conf file, it should happen that, when
    file_status.json is updated after a certain time, no "macos" status should remain stored on the status file.

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
    """
    file_status_json = {}

    log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT,
                      callback=callback_logcollector_started(),
                      error_message="Logcollector did not start")

    # Check if json_status contains 'macos' data and if not insert it
    if exists(LOGCOLLECTOR_FILE_STATUS_PATH):
        file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)
        if 'macos' not in file_status_json:
            file_status_json['macos'] = {}
            file_status_json['macos']['timestamp'] = '2021-10-22 04:59:46.796446-0700'
            file_status_json['macos']['settings'] = 'message CONTAINS "testing"'
            write_json_file(LOGCOLLECTOR_FILE_STATUS_PATH, file_status_json)
    else:
        # If the file does not exist, then is created and then macos data is added
        with open(LOGCOLLECTOR_FILE_STATUS_PATH, 'w') as f:
            pass
        file_status_json['macos'] = {}
        file_status_json['macos']['timestamp'] = '2021-10-22 04:59:46.796446-0700'
        file_status_json['macos']['settings'] = 'message CONTAINS "testing"'
        write_json_file(LOGCOLLECTOR_FILE_STATUS_PATH, file_status_json)

    # Waits for file_status.json to be created, with a timeout about the time needed to update the file
    wait_file(LOGCOLLECTOR_FILE_STATUS_PATH, LOG_COLLECTOR_GLOBAL_TIMEOUT)
    
    # Waits about the time needed to update the file status
    sleep(wait_file_status_update_time)

    file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)

    # Check if json has a structure
    if 'macos' in file_status_json:
        assert False, 'Error, macos should not be present on the status file'
