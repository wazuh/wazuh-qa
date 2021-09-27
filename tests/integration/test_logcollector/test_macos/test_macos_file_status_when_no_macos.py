# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import wazuh_testing.logcollector as logcollector

from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH, LOG_FILE_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.tools.monitoring import FileMonitor, wait_file, make_callback
from wazuh_testing.tools.file import read_json, write_json_file, truncate_file
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.logcollector import prefix as logcollector_prefix
from wazuh_testing.tools.services import control_service
from tempfile import gettempdir
from time import sleep

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_file_status_when_no_macos.yaml')

dummy_file = os.path.join(gettempdir(), 'dummy_file.log')
parameters = [{'FILE_TO_MONITOR': dummy_file}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters)
configuration_ids = [f"{x['FILE_TO_MONITOR']}" for x in parameters]

# Max number of characters to be displayed in the log's debug message
sample_log_length = 100
# Time in seconds to update the file_status.json
file_status_update_time = 4

local_internal_options = { 'logcollector.vcheck_files': file_status_update_time,
                           'logcollector.sample_log_length': sample_log_length }

# Maximum waiting time in seconds to find the logs on ossec.log
file_monitor_timeout = 30

# Time to wait for file_status.json to be updated
wait_file_status_update_time = file_status_update_time + 2

wazuh_log_monitor = None


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def restart_required_logcollector_daemons():
    """Wazuh logcollector daemons handler."""

    required_logcollector_daemons = ['wazuh-logcollector']

    for daemon in required_logcollector_daemons:
        control_service('stop', daemon=daemon)

    truncate_file(LOG_FILE_PATH)
    os.remove(LOGCOLLECTOR_FILE_STATUS_PATH) if os.path.exists(LOGCOLLECTOR_FILE_STATUS_PATH) else None

    for daemon in required_logcollector_daemons:
        control_service('start', daemon=daemon)

    yield

    for daemon in required_logcollector_daemons:
        control_service('stop', daemon=daemon)


@pytest.fixture(scope='module')
def startup_cleanup():
    """Truncate local_internals file and create dummy file to be monitored by logcollector."""
    truncate_file(WAZUH_LOCAL_INTERNAL_OPTIONS)

    with open(dummy_file, 'w') as f:
            pass


def callback_logcollector_started():
    """Check for 'macos' key."""
    return make_callback(pattern='Started', prefix=logcollector_prefix)


def test_macos_file_status_when_no_macos(startup_cleanup,
                                         configure_local_internal_options_module,
                                         get_configuration,
                                         configure_environment,
                                         restart_required_logcollector_daemons):
    """Checks that logcollector does not store and removes, if exists, previous "macos"-formatted localfile data in the
    file_status.json

    Given a file_status.json that contains a valid combination of "settings" and "timestamp" of "macos", when starting
    an agent that has no "macos" localfile configured on its ossec.conf file, it should happen that, when
    file_status.json is updated after a certain time, no "macos" status should remain stored on the status file.

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
    """

    file_status_json = {}

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    wazuh_log_monitor.start(timeout=file_monitor_timeout,
                            callback=callback_logcollector_started(),
                            error_message="Logcollector did not start")

    # Check if json_status contains 'macos' data and if not insert it
    if os.path.exists(LOGCOLLECTOR_FILE_STATUS_PATH):
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
    wait_file(LOGCOLLECTOR_FILE_STATUS_PATH, file_monitor_timeout)

    # Waits about the time needed to update the file status
    sleep(wait_file_status_update_time)

    file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)

    # Check if json has a structure
    if 'macos' in file_status_json:
        assert False, 'Error, macos should not be present on the status file'
