# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import os
import sys
from shutil import rmtree

import pytest
from wazuh_testing import logcollector
from wazuh_testing.tools import LOG_FILE_PATH, monitoring
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration')
configurations_path = os.path.join(test_data_path, 'wazuh_location.yaml')

local_internal_options = {'logcollector.debug': '2'}

if sys.platform == 'win32':
    parameters = [
        {'LOCATION': 'Microsoft-Windows-Sysmon/Operational', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': r'C:\Users\wazuh\myapp\*', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
         'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Application', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'System', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Microsoft-Windows-Sysmon/Operational', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Microsoft-Windows-Windows Defender/Operational', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'File Replication Service', 'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': 'Service Microsoft-Windows-TerminalServices-RemoteConnectionManager',
         'LOG_FORMAT': 'eventchannel'},
        {'LOCATION': r'C:\xampp\apache\logs\*.log', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': r'C:\logs\file-%Y-%m-%d.log', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': r'C:\Testing white spaces', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': r'C:\FOLDER' '\\', 'LOG_FORMAT': 'json'},
    ]

    metadata = [
        {'location': 'Microsoft-Windows-Sysmon/Operational', 'log_format': 'eventchannel'},
        {'location': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
         'log_format': 'eventchannel'},
        {'location': 'Application', 'log_format': 'eventchannel'},
        {'location': 'Security', 'log_format': 'eventchannel'},
        {'location': 'System', 'log_format': 'eventchannel'},
        {'location': 'Microsoft-Windows-Sysmon/Operational', 'log_format': 'eventchannel'},
        {'location': 'Microsoft-Windows-Windows Defender/Operational', 'log_format': 'eventchannel'},
        {'location': 'File Replication Service', 'log_format': 'eventchannel'},
        {'location': 'Service Microsoft-Windows-TerminalServices-RemoteConnectionManager',
         'log_format': 'eventchannel'},
        {'location': r'C:\Users\wazuh\myapp', 'log_format': 'syslog'},
        {'location': r'C:\xampp\apache\logs\*.log', 'log_format': 'syslog'},
        {'location': r'C:\logs\file-%Y-%m-%d.log', 'log_format': 'syslog'},
        {'location': r'C:\Testing white spaces', 'log_format': 'syslog'},
        {'location': r'C:\FOLDER' '\\', 'log_format': 'json'},
    ]
else:
    parameters = [
        {'LOCATION': '/tmp/wazuh-testing/test.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/depth1/depth_test.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/depth1/depth2/depth_test.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/non-existent.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/*', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/Testing white spaces', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/test.*', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/c*test.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/duplicated/duplicated.txt', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/file.log-%Y-%m-%d', 'LOG_FORMAT': 'syslog'},
        {'LOCATION': '/tmp/wazuh-testing/multiple-logs/*', 'LOG_FORMAT': 'syslog'}
    ]

    date = datetime.date.today().strftime("%Y-%m-%d")

    metadata = [
        {'location': '/tmp/wazuh-testing/test.txt', 'files': ['/tmp/wazuh-testing/test.txt'],
         'log_format': 'syslog', 'file_type': 'single_file'},
        {'location': '/tmp/wazuh-testing/depth1/depth_test.txt',
         'files': ['/tmp/wazuh-testing/depth1/depth_test.txt'],
         'log_format': 'syslog', 'file_type': 'single_file'},
        {'location': '/tmp/wazuh-testing/depth1/depth2/depth_test.txt',
         'files': ['/tmp/wazuh-testing/depth1/depth2/depth_test.txt'],
         'log_format': 'syslog', 'file_type': 'single_file'},
        {'location': '/tmp/wazuh-testing/non-existent.txt',
         'files': ['/tmp/wazuh-testing/non-existent.txt'],
         'log_format': 'syslog', 'file_type': 'non_existent_file'},
        {'location': '/tmp/wazuh-testing/*',
         'files': ['/tmp/wazuh-testing/foo.txt', '/tmp/wazuh-testing/bar.log',
                   '/tmp/wazuh-testing/test.yaml', '/tmp/wazuh-testing/ñ.txt',
                   '/tmp/wazuh-testing/テスト.txt', '/tmp/wazuh-testing/ИСПЫТАНИЕ.txt',
                   '/tmp/wazuh-testing/测试.txt', '/tmp/wazuh-testing/اختبار.txt'],
         'log_format': 'syslog', 'file_type': 'wildcard_file'},
        {'location': '/tmp/wazuh-testing/Testing white spaces',
         'files': ['/tmp/wazuh-testing/Testing white spaces'], 'log_format': 'syslog',
         'file_type': 'single_file'},
        {'location': '/tmp/wazuh-testing/test.*',
         'files': ['/tmp/wazuh-testing/test.txt', '/tmp/wazuh-testing/test.log'],
         'log_format': 'syslog', 'file_type': 'wildcard_file'},
        {'location': '/tmp/wazuh-testing/c*test.txt',
         'files': ['/tmp/wazuh-testing/c1test.txt', '/tmp/wazuh-testing/c2test.txt',
                   '/tmp/wazuh-testing/c3test.txt'], 'log_format': 'syslog',
         'file_type': 'wildcard_file'},
        {'location': '/tmp/wazuh-testing/duplicated/duplicated.txt',
         'files': ['/tmp/wazuh-testing/duplicated/duplicated.txt'],
         'log_format': 'syslog', 'file_type': 'duplicated_file'},
        {'location': '/tmp/wazuh-testing/file.log-%Y-%m-%d',
         'files': [f'/tmp/wazuh-testing/file.log-{date}'], 'log_format': 'syslog',
         'file_type': 'single_file'},
        {'location': '/tmp/wazuh-testing/multiple-logs/*', 'files': ['/tmp/wazuh-testing/multiple-logs/multiple'],
         'log_format': 'syslog', 'file_type': 'multiple_logs'}
    ]


# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT']}" for x in parameters]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixtures
@pytest.fixture(scope="module")
def create_directory():
    """Create expected directories."""
    os.makedirs('/tmp/wazuh-testing/multiple-logs', exist_ok=True)
    os.makedirs('/tmp/wazuh-testing/depth1/depth2', exist_ok=True)
    os.makedirs('/tmp/wazuh-testing/duplicated', exist_ok=True)
    yield

    rmtree('/tmp/wazuh-testing')


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

    for file_location in files:
        if file_type == 'non_existent_file':
            pass
        elif file_type == 'non_valid_file':
            with open(file_location, 'a'):
                pass
        elif file_type == 'multiple_logs':
            for i in range(2000):
                name = f'{file_location}{i}.txt'
                with open(name, 'w') as file:
                    file.write(' ')
        else:
            with open(file_location, 'w') as file:
                file.write(' ')
    yield

    for file_location in files:
        if os.path.exists(file_location):
            os.remove(file_location)


def test_location(get_local_internal_options, configure_local_internal_options, create_directory, create_files,
                  get_configuration, configure_environment,
                  restart_logcollector):
    """Check if logcollector is running properly with the specified configuration.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    file_type = get_configuration['metadata']['file_type']
    files = get_configuration['metadata']['files']

    for file_location in sorted(files):
        if file_type == 'single_file':
            log_callback = logcollector.callback_analyzing_file(file_location,
                                                                prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)

            wazuh_log_monitor.start(timeout=60, callback=log_callback,
                                    error_message="The expected 'Analyzing file' message has not been produced")
        elif file_type == 'wildcard_file':
            pattern = get_configuration['metadata']['location']
            log_callback = logcollector.callback_match_pattern_file(pattern, file_location,
                                                                    prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)
            wazuh_log_monitor.start(timeout=60, callback=log_callback,
                                    error_message=f"The expected 'New file that matches the '{pattern}' "
                                                  f"pattern: '{file_location}' message has not been produced")
        elif file_type == 'non_existent_file':
            log_callback = logcollector.callback_non_existent_file(file_location,
                                                                   prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)
            wazuh_log_monitor.start(timeout=60, callback=log_callback,
                                    error_message="The expected ' Could not open file' message has not been produced")
        elif file_type == 'duplicated_file':
            log_callback = logcollector.callback_duplicated_file(file_location,
                                                                 prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)
            wazuh_log_monitor.start(timeout=60, callback=log_callback,
                                    error_message=f"The expected 'Log file '{file_location}' is duplicated' "
                                                  f"message has not been produced")
        elif file_type == 'multiple_logs':
            log_callback = logcollector.callback_file_limit(prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message=f"The expected 'File limit has been reached' "
                                                  f"message has not been produced")
