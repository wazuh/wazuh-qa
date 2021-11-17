# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import tempfile

import pytest
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import time_to_seconds
from wazuh_testing.tools.utils import lower_case_key_dictionary_array


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_age.yaml')

folder_path = os.path.join(tempfile.gettempdir(), 'wazuh_testing_age')
folder_path_regex = os.path.join(folder_path, '*')

local_internal_options = {'logcollector.vcheck_files': 0, 'logcollector.debug': '2', 'windows.debug': '2'}


file_structure = [
    {
        'folder_path': folder_path,
        'filename': ['testing_file_40s.log'],
        'age': 40,
        'content': f'Content of testing_file_40s\n'
    },
    {
        'folder_path': folder_path,
        'filename': ['testing_file_5m.log'],
        'age': 300,
        'content': f'Content of testing_file_5m\n'
    },
    {
        'folder_path': folder_path,
        'filename': ['testing_file_3h.log'],
        'age': 10800,
        'content': f'Content of testing_file_3h\n'
    },
    {
        'folder_path': folder_path,
        'filename': ['testing_file_5d.log'],
        'age': 432000,
        'content': f'Content of testing_file_5d\n'
    },
    {
        'folder_path': folder_path,
        'filename': ['testing_file_300d.log'],
        'age': 25920000,
        'content': f'Content of testing_file_300d\n'
    },
]

parameters = [
    {'LOCATION': folder_path_regex, 'AGE': '4000s'},
    {'LOCATION': folder_path_regex, 'AGE': '5m'},
    {'LOCATION': folder_path_regex, 'AGE': '500m'},
    {'LOCATION': folder_path_regex, 'AGE': '9h'},
    {'LOCATION': folder_path_regex, 'AGE': '200d'},
]

metadata = lower_case_key_dictionary_array(parameters)

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

configuration_ids = [f"{x['location']}_{x['age']}" for x in metadata]


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="function")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get local internal options from the module."""
    return local_internal_options


def test_configuration_age_basic(configure_local_internal_options_module, get_files_list,
                                 create_file_structure_function, get_configuration, configure_environment,
                                 file_monitoring, restart_logcollector):
    """Check if logcollector works correctly and uses the specified age value.

    Check that those files that have not been modified for a time greater than age value, are ignored for logcollector.
    Otherwise, files should not be ignored. Also, it checks logcollector detect modification time changes in monitored
    files and catch new logs from ignored and not ignored files.

    Raises:
        TimeoutError: If the expected callbacks are not generated.
    """

    cfg = get_configuration['metadata']
    age_seconds = time_to_seconds(cfg['age'])

    for file in file_structure:
        for name in file['filename']:
            absolute_file_path = os.path.join(file['folder_path'], name)
            wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

            log_callback = logcollector.callback_match_pattern_file(cfg['location'], absolute_file_path)
            wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                    error_message=f"{name} was not detected")

            if int(age_seconds) <= int(file['age']):
                log_callback = logcollector.callback_ignoring_file(
                    absolute_file_path)
                wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                        error_message=f"{name} was not ignored")

            else:
                with pytest.raises(TimeoutError):
                    log_callback = logcollector.callback_ignoring_file(absolute_file_path)
                    wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                            error_message=f"{name} was not ignored")

    for file in file_structure:
        for name in file['filename']:
            absolute_file_path = os.path.join(file['folder_path'], name)
            with open(absolute_file_path, 'a') as file_to_write:
                file_to_write.write(file['content'])

            log_callback = logcollector.callback_reading_syslog_message(file['content'][:-1])
            wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                    error_message=f"No syslog message received from {name}", update_position=False)
            log_callback = logcollector.callback_read_line_from_file(1, absolute_file_path)
            wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                    error_message=f"No lines read from {name}")
