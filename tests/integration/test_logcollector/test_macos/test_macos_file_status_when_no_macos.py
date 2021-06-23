# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import wazuh_testing.logcollector as logcollector

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_json, write_json_file
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from time import sleep

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_file_status_when_no_macos.yaml')

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__)

file_status_path = os.path.join(WAZUH_PATH, 'queue', 'logcollector', 'file_status.json')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Time in seconds to update the file_status.json
file_status_update_time = 4

local_internal_options = {'logcollector.vcheck_files': str(file_status_update_time)}


@pytest.fixture(scope='module')
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


# Fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


def test_macos_file_status_when_no_macos(get_local_internal_options, configure_local_internal_options,
                                         get_configuration, configure_environment, get_connection_configuration,
                                         init_authd_remote_simulator, restart_logcollector):

    """Checks that logcollector does not store and removes, if exists, previous "macos"-formatted localfile data in the
    file_status.json

    Given a file_status.json that contains a valid combination of "settings" and "timestamp" of "macos", when starting
    an agent that has no "macos" localfile configured on its ossec.conf file, it should happen that, when
    file_status.json is updated after a certain time, no "macos" status should remain stored on the status file.

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
    """

    file_status_json = ''
    # Check if json_status contains 'macos' data and if not insert it
    if os.path.exists(file_status_path):
        file_status_json = read_json(file_status_path)
        if 'macos' not in file_status_json:
            file_status_json['macos'] = {}
            file_status_json['macos']['timestamp'] = '2021-10-22 04:59:46.796446-0700'
            file_status_json['macos']['settings'] = 'message CONTAINS "testing"'
            write_json_file(file_status_path, file_status_json)
    else:
        # If the file does not exist, then is created and then macos data is added
        with open(file_status_path, 'w') as f:
            pass
        file_status_json['macos'] = {}
        file_status_json['macos']['timestamp'] = '2021-10-22 04:59:46.796446-0700'
        file_status_json['macos']['settings'] = 'message CONTAINS "testing"'
        write_json_file(file_status_path, file_status_json)

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    wazuh_log_monitor.start(timeout=15, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    # Waits two times what it should take to logcollector to update the file status
    sleep(file_status_update_time*2)

    file_status_json = read_json(file_status_path)

    # Check if json has a structure
    if 'macos' in file_status_json:
        assert False, 'Error, macos should not be present on the status file'
