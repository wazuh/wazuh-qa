'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if the FIM event
       'maximum number of entries' has the correct value for the monitored files limit of
       the 'file_limit' feature.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_file_limit

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-limit
    - https://en.wikipedia.org/wiki/Inode

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_file_limit
'''
import os
import sys

import pytest

from wazuh_testing import global_parameters, LOG_FILE_PATH, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import create_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import TIER1
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (ERR_MSG_FILE_LIMIT_VALUES, CB_FILE_LIMIT_VALUE,
                                                     ERR_MSG_WRONG_FILE_LIMIT_VALUE, ERR_MSG_FIM_INODE_ENTRIES,
                                                     ERR_MSG_WRONG_INODE_PATH_COUNT, ERR_MSG_WRONG_NUMBER_OF_ENTRIES,
                                                     callback_entries_path_count)
from wazuh_testing.modules.fim.utils import generate_params

# Marks
pytestmark = [TIER1]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]
monitor_timeout = 40

# Configurations

file_limit_list = ['1', '1000']
conf_params = {'TEST_DIRECTORIES': testdir1}

params, metadata = generate_params(extra_params=conf_params,
                                   apply_to_all=({'FILE_LIMIT': file_limit_elem} for
                                                 file_limit_elem in file_limit_list))

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions


def extra_configuration_before_yield():
    """Generate files to fill database"""
    for i in range(0, int(file_limit_list[-1]) + 10):
        create_file(REGULAR, testdir1, f'test{i}')


# Tests
def test_file_limit_values(configure_local_internal_options_module, get_configuration, configure_environment,
                           restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects that the value of the 'entries' tag, which corresponds
                 to the maximum number of files to monitor from the 'file_limit' feature of FIM. For this purpose,
                 the test will monitor a directory. Then, it will check if the FIM event 'maximum number of entries'
                 is generated and has the correct value. Finally, the test will verify that on the FIM event,
                 inodes and monitored files number match.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Set the local_internal_options for the test.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the Wazuh logs file and start a new monitor.

    assertions:
        - Verify that the FIM event 'maximum number of entries' has the correct value
          for the monitored files limit of the 'file_limit' feature.

    input_description: A test case (file_limit_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is
                       combined with the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*Maximum number of entries to be monitored'

    tags:
        - scheduled
    '''
    # Get the file_limit value configured from the wazuh logs
    file_limit_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                               callback=generate_monitoring_callback(CB_FILE_LIMIT_VALUE),
                                               error_message=ERR_MSG_FILE_LIMIT_VALUES).result()
    # assert it matches the expected value
    assert file_limit_value == get_configuration['metadata']['file_limit'], ERR_MSG_WRONG_FILE_LIMIT_VALUE

    # Check number of entries and paths in DB and assert the value matches the expected count
    entries, path_count = wazuh_log_monitor.start(timeout=monitor_timeout, callback=callback_entries_path_count,
                                                  error_message=ERR_MSG_FIM_INODE_ENTRIES).result()

    if sys.platform != 'win32':
        assert (entries == get_configuration['metadata']['file_limit'] and
                path_count == get_configuration['metadata']['file_limit']), ERR_MSG_WRONG_INODE_PATH_COUNT
    else:
        assert entries == str(get_configuration['metadata']['file_limit']), ERR_MSG_WRONG_NUMBER_OF_ENTRIES
