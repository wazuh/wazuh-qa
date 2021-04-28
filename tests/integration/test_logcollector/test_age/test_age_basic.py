# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
import sys
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import time_to_seconds
from datetime import datetime


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_age.yaml')

WINDOWS_FOLDER_PATH = r'C:\testing_age' + '\\'
LINUX_FOLDER_PATH = '/tmp/testing_age/'

local_internal_options = {'logcollector.vcheck_files': 1}

if sys.platform == 'win32':
    folder_path = WINDOWS_FOLDER_PATH
    prefix = AGENT_DETECTOR_PREFIX
else:
    folder_path = LINUX_FOLDER_PATH
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

file_structure = [
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_40s.log",
        "age": 40,
        'content': f'Content of testing_file_40s\n'
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_5m.log",
        "age": 300,
        'content': f'Content of testing_file_40s\n'
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_3h.log",
        "age": 10800,
        'content': f'Content of testing_file_40s\n'
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_5d.log",
        "age": 432000,
        'content': f'Content of testing_file_40s\n'
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_300d.log",
        "age": 25920000,
        'content': f'Content of testing_file_40s\n'
    },
]

parameters = [
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '4000s'},
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '5m'},
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '500m'},
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '9h'},
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '200d'},
]
metadata = [
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '4000s'},
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '5m'},
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '500m'},
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '9h'},
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '200d'},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['AGE']}" for x in parameters]


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="function")
def get_files_list():
    """Get configurations from the module."""
    return file_structure


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


def test_configuration_age_basic(get_local_internal_options, configure_local_internal_options, get_files_list,
                                 create_file_structure, get_configuration, configure_environment, restart_logcollector):
    """

    """
    cfg = get_configuration['metadata']
    age_seconds = time_to_seconds(cfg['age'])
    for file in file_structure:
        wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

        log_callback = logcollector.callback_file_matches_pattern(cfg['location'],
                                                                  f"{file['folder_path']}{file['filename']}",
                                                                  prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message='No testing file detected')
        if int(age_seconds) <= int(file['age']):
            log_callback = logcollector.callback_ignoring_file(
                f"{file['folder_path']}{file['filename']}", prefix=prefix)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message='Testing file was not ignored')

            f = open(f"{file['folder_path']}{file['filename']}", "a")
            f.write(file['content'])
            f.close()

            log_callback = logcollector.callback_reading_syslog_message(file['content'][:-1], prefix=prefix)
            wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                    error_message='Testing file was not ignored')

            log_callback = logcollector.callback_read_line_from_file(1, f"{file['folder_path']}{file['filename']}",
                                                                        prefix=prefix)
            wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                    error_message='Testing file was not ignored')

        else:
            with pytest.raises(TimeoutError):
                log_callback = logcollector.callback_ignoring_file(
                    f"{file['folder_path']}{file['filename']}", prefix=prefix)
                wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                        error_message='Testing file was not ignored')