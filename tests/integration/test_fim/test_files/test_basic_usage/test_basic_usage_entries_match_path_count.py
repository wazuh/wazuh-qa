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
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, SYMLINK, HARDLINK, \
    check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import callback_entries_path_count

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir1', 'subdir')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2, testdir1_subdir = test_directories

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m, )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def extra_configuration_before_yield():
    create_file(REGULAR, testdir1, 'test_1', content='')
    create_file(REGULAR, testdir1, 'test_2', content='')
    create_file(SYMLINK, testdir1, 'symlink', target=os.path.join(testdir1, 'test_1'))
    create_file(HARDLINK, testdir1, 'hardlink', target=os.path.join(testdir1, 'test_2'))


def test_entries_match_path_count(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
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
        - time_travel
    '''
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    entries, path_count = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_entries_path_count,
                                                  error_message='Did not receive expected '
                                                                '"Fim inode entries: ..., path count: ..." event'
                                                  ).result()
    check_time_travel(True, monitor=wazuh_log_monitor)

    if entries and path_count:
        assert entries == '3' and path_count == '4', 'Wrong number of inodes and path count'
    else:
        raise AssertionError('Wrong number of inodes and path count')
