# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import fnmatch
import os
import sys
import tempfile
from shutil import rmtree

import pytest
from wazuh_testing import logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration')
configurations_path = os.path.join(test_data_path, 'wazuh_location.yaml')

local_internal_options = {'logcollector.debug': '2'}

temp_dir = tempfile.gettempdir()

if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

if sys.platform == 'win32':
    parameters = [
        {'LOCATION': fr'{temp_dir}\wazuh-testing\test*', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\*.log'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\*test.txt', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\*test.txt'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\*test*', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\*.log'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\test*', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\test*'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\*test.txt', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\test*'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\*test*', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\test*'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\test*', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\*test*'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\*test.txt', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\*test*'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\*test*', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\*test*'},
        {'LOCATION': fr'{temp_dir}\wazuh-testing\*', 'LOG_FORMAT': 'syslog',
         'EXCLUDE': fr'{temp_dir}\wazuh-testing\*'}
    ]

    metadata = [
        {'location': fr'{temp_dir}\wazuh-testing\test*',
         'files': [fr'{temp_dir}\wazuh-testing\test.txt', fr'{temp_dir}\wazuh-testing\test1.log',
                   fr'{temp_dir}\wazuh-testing\test2.log'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\*.log',
         'expected_matches': [fr'{temp_dir}\wazuh-testing\test.txt'],
         'description': 'Testing right wildcard, left exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\*test.txt',
         'files': [fr'{temp_dir}\wazuh-testing\1test.txt', fr'{temp_dir}\wazuh-testing\2test.txt',
                   fr'{temp_dir}\wazuh-testing\0test.txt'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\*test.txt', 'expected_matches': ['none'],
         'description': 'Testing left wildcard, left exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\*test*',
         'files': [fr'{temp_dir}\wazuh-testing\1test1.txt', fr'{temp_dir}\wazuh-testing\1test1.log',
                   fr'{temp_dir}\wazuh-testing\2test2.log'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\*.log',
         'expected_matches': [fr'{temp_dir}\wazuh-testing\1test1.txt'],
         'description': 'Testing right and left wildcard, left exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\test*',
         'files': [fr'{temp_dir}\wazuh-testing\test1.txt', fr'{temp_dir}\wazuh-testing\test1.log',
                   fr'{temp_dir}\wazuh-testing\test2.log'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\test*', 'expected_matches': ['none'],
         'description': 'Testing right wildcard, right exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\*test.txt',
         'files': [fr'{temp_dir}\wazuh-testing\1test.txt', fr'{temp_dir}\wazuh-testing\2test.txt',
                   fr'{temp_dir}\wazuh-testing\test.txt'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\test*',
         'expected_matches': [fr'{temp_dir}\wazuh-testing\1test.txt', fr'{temp_dir}\wazuh-testing\2test.txt'],
         'description': 'Testing left wildcard, right exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\*test*',
         'files': [fr'{temp_dir}\wazuh-testing\1test1.txt', fr'{temp_dir}\wazuh-testing\1test1.log',
                   fr'{temp_dir}\wazuh-testing\2test2.log', fr'{temp_dir}\wazuh-testing\test2.txt'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\test*',
         'expected_matches': [fr'{temp_dir}\wazuh-testing\1test1.txt', fr'{temp_dir}\wazuh-testing\1test1.log',
                              fr'{temp_dir}\wazuh-testing\2test2.log'],
         'description': 'Testing right and left wildcard, right exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\test*',
         'files': [fr'{temp_dir}\wazuh-testing\test1.txt', fr'{temp_dir}\wazuh-testing\test1.log',
                   fr'{temp_dir}\wazuh-testing\test2.log'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}/wazuh-testing/*test*',
         'expected_matches': ['none'],
         'description': 'Testing right wildcard, right and left exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\*test.txt',
         'files': [fr'{temp_dir}\wazuh-testing\1test.txt', fr'{temp_dir}\wazuh-testing\2test.txt'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\*test*',
         'expected_matches': ['none'],
         'description': 'Testing left wildcard, right and left exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\*test*',
         'files': [fr'{temp_dir}\wazuh-testing\1test1.txt', fr'{temp_dir}\wazuh-testing\1test1.log',
                   fr'{temp_dir}\wazuh-testing\2test2.log', fr'{temp_dir}\wazuh-testing\test2.txt'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\*test*',
         'expected_matches': ['none'],
         'description': 'Testing right and left wildcard, right and left exclude'},
        {'location': fr'{temp_dir}\wazuh-testing\*',
         'files': [fr'{temp_dir}\wazuh-testing\1test1.txt', fr'{temp_dir}\wazuh-testing\1test1.log',
                   fr'{temp_dir}\wazuh-testing\2test2.log', fr'{temp_dir}\wazuh-testing\test2.txt'],
         'log_format': 'syslog', 'exclude': fr'{temp_dir}\wazuh-testing\*',
         'expected_matches': ['none'],
         'description': 'Testing wildcard location'}

    ]
else:
    parameters = [
        {'LOCATION': '/tmp/wazuh-testing/test*', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/*.log'},
        {'LOCATION': '/tmp/wazuh-testing/*test.txt', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/*test.txt'},
        {'LOCATION': '/tmp/wazuh-testing/*test*', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/*.log'},
        {'LOCATION': '/tmp/wazuh-testing/test*', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/test*'},
        {'LOCATION': '/tmp/wazuh-testing/*test.txt', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/test*'},
        {'LOCATION': '/tmp/wazuh-testing/*test*', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/test*'},
        {'LOCATION': '/tmp/wazuh-testing/test*', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/*test*'},
        {'LOCATION': '/tmp/wazuh-testing/*test.txt', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/*test*'},
        {'LOCATION': '/tmp/wazuh-testing/*test*', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/*test*'},
        {'LOCATION': '/tmp/wazuh-testing/*', 'LOG_FORMAT': 'syslog', 'EXCLUDE': '/tmp/wazuh-testing/*'}
    ]

    metadata = [
        {'location': '/tmp/wazuh-testing/test*',
         'files': ['/tmp/wazuh-testing/test.txt', '/tmp/wazuh-testing/test1.log', '/tmp/wazuh-testing/test2.log'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/*.log',
         'expected_matches': ['/tmp/wazuh-testing/test.txt'],
         'description': 'Testing right wildcard, left exclude'},
        {'location': '/tmp/wazuh-testing/*test.txt',
         'files': ['/tmp/wazuh-testing/1test.txt', '/tmp/wazuh-testing/2test.txt', '/tmp/wazuh-testing/test.txt'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/*test.txt', 'expected_matches': ['none'],
         'description': 'Testing left wildcard, left exclude'},
        {'location': '/tmp/wazuh-testing/*test*',
         'files': ['/tmp/wazuh-testing/1test1.txt', '/tmp/wazuh-testing/1test1.log', '/tmp/wazuh-testing/2test2.log'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/*.log',
         'expected_matches': ['/tmp/wazuh-testing/1test1.txt'],
         'description': 'Testing right and left wildcard, left exclude'},
        {'location': '/tmp/wazuh-testing/test*',
         'files': ['/tmp/wazuh-testing/test1.txt', '/tmp/wazuh-testing/test1.log', '/tmp/wazuh-testing/test2.log'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/test*', 'expected_matches': ['none'],
         'description': 'Testing right wildcard, right exclude'},
        {'location': '/tmp/wazuh-testing/*test.txt',
         'files': ['/tmp/wazuh-testing/1test.txt', '/tmp/wazuh-testing/2test.txt', '/tmp/wazuh-testing/test.txt'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/test*',
         'expected_matches': ['/tmp/wazuh-testing/1test.txt', '/tmp/wazuh-testing/2test.txt'],
         'description': 'Testing left wildcard, right exclude'},
        {'location': '/tmp/wazuh-testing/*test*',
         'files': ['/tmp/wazuh-testing/1test1.txt', '/tmp/wazuh-testing/1test1.log', '/tmp/wazuh-testing/2test2.log',
                   '/tmp/wazuh-testing/test2.txt'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/test*',
         'expected_matches': ['/tmp/wazuh-testing/1test1.txt', '/tmp/wazuh-testing/1test1.log',
                              '/tmp/wazuh-testing/2test2.log'],
         'description': 'Testing right and left wildcard, right exclude'},
        {'location': '/tmp/wazuh-testing/test*',
         'files': ['/tmp/wazuh-testing/test1.txt', '/tmp/wazuh-testing/test1.log', '/tmp/wazuh-testing/test2.log'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/*test*',
         'expected_matches': ['none'],
         'description': 'Testing right wildcard, right and left exclude'},
        {'location': '/tmp/wazuh-testing/*test.txt',
         'files': ['/tmp/wazuh-testing/1test.txt', '/tmp/wazuh-testing/2test.txt'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/*test*',
         'expected_matches': ['none'],
         'description': 'Testing left wildcard, right and left exclude'},
        {'location': '/tmp/wazuh-testing/*test*',
         'files': ['/tmp/wazuh-testing/1test1.txt', '/tmp/wazuh-testing/1test1.log', '/tmp/wazuh-testing/2test2.log',
                   '/tmp/wazuh-testing/test2.txt'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/*test*',
         'expected_matches': ['none'],
         'description': 'Testing right and left wildcard, right and left exclude'},
        {'location': '/tmp/wazuh-testing/*',
         'files': ['/tmp/wazuh-testing/1test1.txt', '/tmp/wazuh-testing/1test1.log', '/tmp/wazuh-testing/2test2.log',
                   '/tmp/wazuh-testing/test2.txt'],
         'log_format': 'syslog', 'exclude': '/tmp/wazuh-testing/*',
         'expected_matches': ['none'],
         'description': 'Testing wildcard location'}

    ]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT']}" for x in parameters]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixtures
@pytest.fixture(scope="module")
def create_directory():
    """Create expected directories."""
    if sys.platform == 'win32':
        os.makedirs(fr'{temp_dir}\wazuh-testing', exist_ok=True)
    else:
        os.makedirs('/tmp/wazuh-testing', exist_ok=True)
    yield

    if sys.platform == 'win32':
        rmtree(fr'{temp_dir}\wazuh-testing', ignore_errors=True)
    else:
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

    for file_location in files:
        with open(file_location, 'w+') as file:
            file.write(' ')
    yield

    for file_location in files:
        if os.path.exists(file_location):
            os.remove(file_location)


def test_exclude(get_local_internal_options, configure_local_internal_options, create_directory, create_files,
                 get_configuration, configure_environment,
                 restart_logcollector):
    """Check if logcollector is excluding specified files.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    files = get_configuration['metadata']['files']
    excluded = get_configuration['metadata']['exclude']

    for file_location in sorted(files):
        match = fnmatch.fnmatch(file_location, excluded)
        if match:
            log_callback = logcollector.callback_excluded_file(file_location,
                                                               prefix=prefix)
            wazuh_log_monitor.start(timeout=60, callback=log_callback, error_message=f"The expected 'File excluded: "
                                                                                     f"'{file_location}' message has "
                                                                                     f"not been produced")
