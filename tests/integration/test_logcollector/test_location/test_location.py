# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import os
import sys
import tempfile
from shutil import rmtree

import pytest
from wazuh_testing import logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration')
configurations_path = os.path.join(test_data_path, 'wazuh_location.yaml')

local_internal_options = {'logcollector.debug': '2'}

temp_dir = tempfile.gettempdir()
date = datetime.date.today().strftime("%Y-%m-%d")

parameters = [
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'depth1', 'test.txt'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'depth1', ' depth_test.txt'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'depth1', 'depth2', 'depth_test.txt'),
     'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'non-existent.txt'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'Testing white spaces'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test.*'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'c*test.txt'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'duplicated', 'duplicated.txt'),
     'LOG_FORMAT': 'syslog', 'PATH_2': os.path.join(temp_dir, 'wazuh-testing', 'duplicated', 'duplicated.txt')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'file.log-%Y-%m-%d'), 'LOG_FORMAT': 'syslog'},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'multiple-logs', '*'), 'LOG_FORMAT': 'syslog'}
]

metadata = [
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'depth1', 'test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'depth1', 'test.txt')],
     'log_format': 'syslog', 'file_type': 'single_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'depth1', ' depth_test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'depth1', ' depth_test.txt')],
     'log_format': 'syslog', 'file_type': 'single_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'depth1', 'depth2', 'depth_test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'depth1', 'depth2', 'depth_test.txt')],
     'log_format': 'syslog', 'file_type': 'single_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'non-existent.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'non-existent.txt')],
     'log_format': 'syslog', 'file_type': 'non_existent_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'foo.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'bar.log'),
               os.path.join(temp_dir, 'wazuh-testing', 'test.yaml'),
               os.path.join(temp_dir, 'wazuh-testing', 'ñ.txt')],
     'log_format': 'syslog', 'file_type': 'wildcard_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'Testing white spaces'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'Testing white spaces')], 'log_format': 'syslog',
     'file_type': 'single_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test.*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'test.log')],
     'log_format': 'syslog', 'file_type': 'wildcard_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'c*test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'c1test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'c2test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'c3test.txt')], 'log_format': 'syslog',
     'file_type': 'wildcard_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'duplicated', 'duplicated.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'duplicated', 'duplicated.txt')],
     'log_format': 'syslog', 'path_2': os.path.join(temp_dir, 'wazuh-testing', 'duplicated', 'duplicated.txt'),
     'file_type': 'duplicated_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'file.log-%Y-%m-%d'),
     'files': [os.path.join(temp_dir, 'wazuh-testing',f'file.log-{date}')], 'log_format': 'syslog',
     'file_type': 'single_file'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'multiple-logs', '*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'multiple-logs', 'multiple')],
     'log_format': 'syslog', 'file_type': 'multiple_logs'}
]

if sys.platform != 'win32':
    for case in metadata:
        if case['location'] == os.path.join(temp_dir, 'wazuh-testing', '*'):
            case['files'].append(os.path.join(temp_dir, 'wazuh-testing', 'テスト.txt'))
            case['files'].append(os.path.join(temp_dir, 'wazuh-testing', 'ИСПЫТАНИЕ.txt'))
            case['files'].append(os.path.join(temp_dir, 'wazuh-testing', '测试.txt'))
            case['files'].append(os.path.join(temp_dir, 'wazuh-testing', 'اختبار.txt'))

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION']}_{x['LOG_FORMAT']}" for x in parameters]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixtures
@pytest.fixture(scope="module")
def create_directory():
    """Create expected directories."""
    os.makedirs(os.path.join(temp_dir, 'wazuh-testing', 'multiple-logs'), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, 'wazuh-testing', 'depth1', 'depth2'), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, 'wazuh-testing', 'duplicated'), exist_ok=True)
    yield
    rmtree(os.path.join(temp_dir, 'wazuh-testing'), ignore_errors=True)


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


@pytest.fixture(scope='module')
def create_files(request, get_configuration):
    """Create expected files."""
    files = get_configuration['metadata']['files']
    file_type = get_configuration['metadata']['file_type']

    if file_type != 'non_existent_file':
        for file_location in files:
            if file_type == 'multiple_logs':
                for i in range(2000):
                    open(f'{file_location}{i}.txt', 'w').close()
            else:
                open(file_location, 'w').close()
    yield

    for file_location in files:
        if os.path.exists(file_location):
            os.remove(file_location)


def test_location(get_local_internal_options, configure_local_internal_options, create_directory, create_files,
                  get_configuration, configure_environment, restart_logcollector):
    """Check if logcollector is running properly with the specified configuration.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    file_type = get_configuration['metadata']['file_type']
    files = get_configuration['metadata']['files']

    for file_location in sorted(files):
        if file_type == 'single_file':
            log_callback = logcollector.callback_analyzing_file(file_location)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                    error_message="The expected 'Analyzing file' message has not been produced")
        elif file_type == 'wildcard_file':
            pattern = get_configuration['metadata']['location']
            log_callback = logcollector.callback_match_pattern_file(pattern, file_location)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                    error_message=f"The expected 'New file that matches the '{pattern}' "
                                                  f"pattern: '{file_location}' message has not been produced")
        elif file_type == 'non_existent_file':
            log_callback = logcollector.callback_non_existent_file(file_location)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                    error_message="The expected 'Could not open file' message has not been produced")
        elif file_type == 'duplicated_file':
            log_callback = logcollector.callback_duplicated_file(file_location)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                    error_message=f"The expected 'Log file '{file_location}' is duplicated' "
                                                  f"message has not been produced")
        elif file_type == 'multiple_logs':
            log_callback = logcollector.callback_file_limit()
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                    error_message=f"The expected 'File limit has been reached' "
                                                  f"message has not been produced")
