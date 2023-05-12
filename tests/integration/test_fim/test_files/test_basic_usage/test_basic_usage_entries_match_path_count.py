'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. In particular, these tests will verify that when using 'hard' and
       'symbolic' links, the FIM events contain the number of inodes and paths to files consistent.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_basic_usage

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows
    - macos
    - solaris

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
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
    - fim_basic_usage
'''
import os

import pytest
from wazuh_testing import T_20, LOG_FILE_PATH, REGULAR, SYMLINK, HARDLINK
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.file import create_file
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import callback_entries_path_count
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# variables
test_folders = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_folders)
file_list = [{'type': REGULAR, 'path': test_folders[0], 'name':'test_1', 'content':''},
             {'type': REGULAR, 'path': test_folders[0], 'name':'test_2', 'content':''},
             {'type': SYMLINK, 'path': test_folders[0], 'name':'symlink', 'target':os.path.join(test_folders[0], 'test_1')},
             {'type': HARDLINK, 'path': test_folders[0], 'name':'hardlink', 'target':os.path.join(test_folders[0], 'test_2')}]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_basic_usage_entries_match_path_count.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_basic_usage.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = directory_str
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_entries_match_path_count(configuration, metadata, test_folders, file_list, set_wazuh_configuration,
                       create_monitored_folders, configure_local_internal_options_function, 
                       create_files_before_test, restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if FIM events contain the correct number of file paths when 'hard'
                 and 'symbolic' links are used. For this purpose, the test will monitor
                 a testing folder and create two regular files, a 'symlink' and a 'hard link'
                 before the scan starts. Finally, it verifies in the generated FIM event
                 that three inodes and four file paths are detected.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that when using hard and symbolic links, the FIM events contain
          the number of inodes and paths to files consistent.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Fim inode entries*, path count' (If the OS used is not Windows)
        - r'.*Fim entries' (If the OS used is Windows)

    tags:
        - scheduled
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Wait for scan and get entries and path_count
    entries, path_count = wazuh_log_monitor.start(timeout=T_20, callback=callback_entries_path_count,
                                                  error_message='Did not receive expected '
                                                                '"Fim inode entries: ..., path count: ..." event'
                                                  ).result()

    if entries and path_count:
        assert entries == '3', 'Wrong number of inodes found' 
        assert path_count == '4', 'Wrong number path_count found'
    else:
        raise AssertionError('Wrong number of inodes and path count')

