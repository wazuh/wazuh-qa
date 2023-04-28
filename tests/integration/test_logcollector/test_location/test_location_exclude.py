'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages.
       Specifically, these tests will check if the logcollector ignores the files set in the
       'exclude' tag when monitoring a log folder. Log data collection is the real-time process
       of making sense out of the records generated by servers or devices. This component can
       receive logs through text files or Windows event logs. It can also directly receive logs
       via remote syslog which is useful for firewalls and other such devices.

components:
    - logcollector

suite: location

targets:
    - agent
    - manager

daemons:
    - wazuh-logcollector

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#location
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#exclude

tags:
    - logcollector_location
'''
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
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration_template')
configurations_path = os.path.join(test_data_path, 'wazuh_location.yaml')

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
     'log_format': 'syslog', 'exclude': os.path.join(temp_dir, 'wazuh-testing', '*.log'),
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
     'expected_matches': [os.path.join(temp_dir, 'wazuh-testing', ' 1test.txt'),
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
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


def test_location_exclude(get_files_list, create_file_structure_module, get_configuration, configure_environment,
                          restart_logcollector):
    '''
    description: Check if the 'wazuh-logcollector' excludes the files specified in the 'exclude' tag. For this
                 purpose, the test will create several testing log files and configure a 'localfile' section
                 to monitor the folder where they are located, and set the 'exclude' tag with different values,
                 including wildcards. Finally, the test will verify that only the matched files are excluded by
                 checking the 'exclude' events generated.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_files_list:
            type: fixture
            brief: Get file list to create from the module.
        - create_file_structure_module:
            type: fixture
            brief: Create the specified file tree structure.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_logcollector:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the logcollector ignores only the log files that match the exclude tag.

    input_description: A configuration template (test_location) is contained in an external YAML file
                       (wazuh_location.yaml). That template is combined with different test cases defined
                       in the module. Those include configuration settings for the 'wazuh-logcollector' daemon.

    expected_output:
        - r'File excluded'

    tags:
        - logs
    '''
    files = get_configuration['metadata']['files']
    excluded = get_configuration['metadata']['exclude']

    for file_location in sorted(files):
        match = fnmatch.fnmatch(file_location, excluded)
        if match:
            log_callback = logcollector.callback_excluded_file(file_location)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT,
                                    callback=log_callback,
                                    error_message=f"The expected 'File excluded: "
                                                  f"'{file_location}' message has "
                                                  f"not been produced")
