'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM limits the number
       of file descriptors that can open when using the 'realtime' monitoring mode in Windows
       systems. That limit is set in the 'max_fd_win_rt' internal option.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_inotify

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
    - https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#syscheck

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_inotify
'''
import os
import shutil
import pytest
import wazuh_testing.fim as fim
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

test_folder = os.path.join(PREFIX, 'test_folder')
test_directories = [test_folder]
fd_rt_value = 2

created_dirs = [os.path.join(test_folder, 'test1'),
                os.path.join(test_folder, 'test2')]

extra_dirs = [os.path.join(test_folder, 'test3'),
              os.path.join(test_folder, 'test4')]
# Add all paths to the monitoring
dir_str = ','.join(created_dirs + extra_dirs)

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_max_fd.yaml')

# Configurations

conf_params = {'TEST_DIRECTORIES': dir_str}
parameters, metadata = fim.generate_params(extra_params=conf_params, modes=['realtime'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def extra_configuration_before_yield():
    for dir in created_dirs:
        if not os.path.exists(dir):
            os.mkdir(dir)
    fim.change_internal_options(param='syscheck.max_fd_win_rt', value=fd_rt_value)


def extra_configuration_after_yield():
    fim.change_internal_options(param='syscheck.max_fd_win_rt', value=256)


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh-qa#2174")
@pytest.mark.parametrize('tags_to_apply', [{'test_max_fd_rt'}])
def test_max_fd_win_rt(tags_to_apply, get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the number of file descriptors that can open when
                 using the 'realtime' monitoring mode. That limit is set in the 'max_fd_win_rt' internal option.
                 For this purpose, the test will monitor four folders, two of them are created before FIM starts,
                 setting the limit to two folders. Once FIM is started, the test will remove the two existing
                 folders and create them again, verifying that FIM events are triggered. Then, it will remove
                 those two folders, and finally, the test will create another two folders and verify that
                 FIM events are generated.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
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
        - Verify that FIM events are generated when changes are made in monitored folders
          that are deleted and created again.
        - Verify that FIM events are generated when making changes in the new monitored folders.

    input_description: A test case (test_max_fd_rt) is contained in external YAML file (wazuh_conf_max_fd.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Realtime watch deleted for'
        - r'.*Directory added for real time monitoring'
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - realtime
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    for dir in created_dirs:
        shutil.rmtree(dir)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_delete_watch,
                                error_message='Did not receive expected "Deleted realtime watch ..." event')

        os.mkdir(dir)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=fim.callback_realtime_added_directory,
                                error_message='Did not receive expected "Directory added for realtime ..." event')

        fim.regular_file_cud(dir, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, time_travel=False)
        shutil.rmtree(dir)

    for dir in extra_dirs:
        os.mkdir(dir)
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=fim.callback_realtime_added_directory,
                                error_message='Did not receive expected "Directory added for realtime ..." event')
        fim.regular_file_cud(dir, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, time_travel=False)
