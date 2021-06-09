# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
from json import load
import tempfile

import pytest
import wazuh_testing.tools.configuration as conf
from wazuh_testing import logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service


# Marks
pytestmark = pytest.mark.tier(level=1)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration')
configurations_path = os.path.join(test_data_path, 'wazuh_configuration.yaml')

temp_dir = tempfile.gettempdir()

file_structure = [
    {
        'folder_path': os.path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.txt'],
        'content': f'Content of testing_file\n'
    }
]

parameters = [
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'), 'LOG_FORMAT': 'syslog'},
]

metadata = [
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'test.txt')],
     'log_format': 'syslog'}
]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION']}_{x['LOG_FORMAT']}" for x in parameters]
state_interval = [1, 2, 3, 4, 5]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.fixture(scope="module", params=state_interval)
def get_local_internal_options(request):
    """Get configurations from the module."""
    backup_options_lines = conf.get_wazuh_local_internal_options()

    if sys.platform == 'win32':
        conf.add_wazuh_local_internal_options({'\n windows.debug': '2'})
    else:
        conf.add_wazuh_local_internal_options({'\n logcollector.debug': '2'})

    conf.add_wazuh_local_internal_options({'logcollector.state_interval': request.param})

    control_service('restart')

    yield request.param
    conf.set_wazuh_local_internal_options(backup_options_lines)
    control_service('restart')


def test_options_state_interval_no_file(get_local_internal_options, get_files_list, create_file_structure_module,
                                        get_configuration, configure_environment, restart_logcollector):
    """Check if the monitorized file does not appear in logcollector.state when it is removed.

    Raises:
        AssertionError: If the elapsed time is different from the interval.
        TimeoutError: If the expected callback is not generated.
    """

    interval = get_local_internal_options

    for file in get_files_list:
        for name in file['filename']:
            # Ensure file is analyzed
            log_path = os.path.join(file['folder_path'], name)
            with open(log_path, 'w') as log_file:
                log_file.write('Modifying the file')

            log_callback = logcollector.callback_analyzing_file(log_path)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message="ERROR GENERIC CHANGE")

            # Ensure LOGCOLLECTOR STATISTICS FILE FILE is created
            logcollector.wait_statistics_file(timeout=interval + 5)

            with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as json_file:
                data = load(json_file)

            global_files = data['global']['files']
            interval_files = data['interval']['files']

            assert list(filter(lambda global_file: global_file['location'] == log_path, global_files))
            assert list(filter(lambda interval_file: interval_file['location'] == log_path, interval_files))

            os.remove(log_path)

            # Ensure logcollector has detected deletion of the file
            log_callback = logcollector.callback_removed_file(log_path)
            wazuh_log_monitor.start(timeout=30, callback=log_callback,
                                    error_message="ERROR GENERIC CHANGE")

            with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as next_json_file:
                data = load(next_json_file)

            global_files = data['global']['files']
            interval_files = data['interval']['files']

            assert not list(filter(lambda global_file: global_file['location'] == log_path, global_files))
            assert not list(filter(lambda interval_file: interval_file['location'] == log_path, interval_files))

