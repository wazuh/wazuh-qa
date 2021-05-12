# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import fnmatch
import os
import tempfile

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

file_structure = [
    {
        'folder_path': os.path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.txt', 'test1.log', 'test2.log', '1test.txt', '2test.txt', '1test1.txt', '1test1.log',
                     '2test2.log', 'test1.txt', 'test2.txt'],
        'content': f'Content of testing_file\n'
    },
]

parameters = [
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test*'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', '*.log')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*test.txt'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', '*test.txt')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*test*'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', '*.log')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test*'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', 'test*')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*test.txt'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', 'test*')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*test*'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', 'test*')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test*'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', '*test*')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*test.txt'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', '*test*')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*test*'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', '*test*')},
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', '*'), 'LOG_FORMAT': 'syslog',
     'EXCLUDE': os.path.join(temp_dir, 'wazuh-testing', '*')}
]

metadata = [
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'test1.log'),
               os.path.join(temp_dir, 'wazuh-testing', 'test2.log')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', '*.log'),
     'expected_matches': [os.path.join(temp_dir, 'wazuh-testing', 'test.txt')],
     'description': 'Testing right wildcard, left exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', '1test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', '2test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'test.txt')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', '*test.txt'),
     'expected_matches': ['none'],
     'description': 'Testing left wildcard, left exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*test*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', '1test1.txt'),
               os.path.join(temp_dir, 'wazuh-testing', '1test1.log'),
               os.path.join(temp_dir, 'wazuh-testing', '2test2.log')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing','*.log'),
     'expected_matches': [os.path.join(temp_dir, 'wazuh-testing', '1test1.txt')],
     'description': 'Testing right and left wildcard, left exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'test1.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'test1.log'),
               os.path.join(temp_dir, 'wazuh-testing', 'test2.log')],
     'log_format': 'syslog', 'exclude':os.path.join(temp_dir, 'wazuh-testing', 'test*'),
     'expected_matches': ['none'],
     'description': 'Testing right wildcard, right exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', '1test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', '2test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'test.txt')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', 'test*'),
     'expected_matches': [os.path.join(temp_dir, 'wazuh-testing',' 1test.txt'),
                          os.path.join(temp_dir, 'wazuh-testing', '2test.txt')],
     'description': 'Testing left wildcard, right exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*test*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', '1test1.txt'),
               os.path.join(temp_dir, 'wazuh-testing', '1test1.log'),
               os.path.join(temp_dir, 'wazuh-testing', '2test2.log'),
               os.path.join(temp_dir, 'wazuh-testing', 'test2.txt')],
     'log_format': 'syslog', 'exclude':os.path.join(temp_dir, 'wazuh-testing', 'test*'),
     'expected_matches': [os.path.join(temp_dir, 'wazuh-testing', '1test1.txt'),
                          os.path.join(temp_dir, 'wazuh-testing', '1test1.log'),
                          os.path.join(temp_dir, 'wazuh-testing', '2test2.log')],
     'description': 'Testing right and left wildcard, right exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', 'test1.txt'),
               os.path.join(temp_dir, 'wazuh-testing', 'test1.log'),
               os.path.join(temp_dir, 'wazuh-testing', 'test2.log')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', '*test*'),
     'expected_matches': ['none'],
     'description': 'Testing right wildcard, right and left exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*test.txt'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', '1test.txt'),
               os.path.join(temp_dir, 'wazuh-testing', '2test.txt')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', '*test*'),
     'expected_matches': ['none'],
     'description': 'Testing left wildcard, right and left exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*test*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', '1test1.txt'),
               os.path.join(temp_dir, 'wazuh-testing', '1test1.log'),
               os.path.join(temp_dir, 'wazuh-testing', '2test2.log'),
               os.path.join(temp_dir, 'wazuh-testing', 'test2.txt')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', '*test*'),
     'expected_matches': ['none'],
     'description': 'Testing right and left wildcard, right and left exclude'},
    {'location': os.path.join(temp_dir, 'wazuh-testing', '*'),
     'files': [os.path.join(temp_dir, 'wazuh-testing', '1test1.txt'),
               os.path.join(temp_dir, 'wazuh-testing', '1test1.log'),
               os.path.join(temp_dir, 'wazuh-testing', '2test2.log'),
               os.path.join(temp_dir, 'wazuh-testing', 'test2.txt')],
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', '*'),
     'expected_matches': ['none'],
     'description': 'Testing wildcard location'}

]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION']}_{x['LOG_FORMAT']}" for x in parameters]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


def test_location_exclude(get_local_internal_options, configure_local_internal_options, create_file_structure_module,
                 get_configuration, configure_environment, restart_logcollector):
    """Check if logcollector is excluding specified files.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """
    files = get_configuration['metadata']['files']
    excluded = get_configuration['metadata']['exclude']

    for file_location in sorted(files):
        match = fnmatch.fnmatch(file_location, excluded)
        if match:
            log_callback = logcollector.callback_excluded_file(file_location)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback, error_message=f"The expected 'File excluded: "
                                                                                     f"'{file_location}' message has "
                                                                                     f"not been produced")
