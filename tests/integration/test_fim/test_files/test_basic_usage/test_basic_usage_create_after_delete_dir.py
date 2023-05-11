'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. In particular, these tests will check if FIM events are still generated when
       a monitored directory is deleted and created again.
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

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
import shutil
import sys
import time

import pytest
from wazuh_testing import T_20, LOG_FILE_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.modules.fim.utils import regular_file_cud
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

directory_str = os.path.join(PREFIX, 'testdir1')
test_folders = [directory_str]
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#4153")

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_basic_usage_create_after_delete_dir.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_basic_usage.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = directory_str
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)


@mark_skip_agentWindows
@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_create_after_delete(configuration, metadata, test_folders, set_wazuh_configuration,
                             create_monitored_folders_module, configure_local_internal_options_function,
                             restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if a monitored directory keeps reporting FIM events after deleting and creating it again.
                 Under Windows systems, it verifies that the directory watcher is refreshed (checks the SACLs)
                 after directory re-creation one second after. For this purpose, the test creates the testing
                 directory to be monitored, checks that FIM events are generated, and then deletes it.
                 Finally, it creates the directory again and verifies that the events are still generated correctly.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
        - file_list:
            type: dict
            brief: List of files to be created before test starts.
        - create_files_before_test:    
            type: fixture
            brief: create a given list of files before the test starts.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders:
            type: fixture
            brief: Create a given list of folders when the test starts. Delete the folders at the end of the module.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options.conf file.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.
        - wait_syscheck_start:
            type: fixture
            brief: check that the starting FIM scan is detected.

    assertions:
        - Verify that FIM events are still generated when a monitored directory is deleted and created again.

    input_description: A test case (ossec_conf) is contained in external YAML file
                       (wazuh_conf.yaml or wazuh_conf_win32.yaml) which includes configuration
                       settings for the 'wazuh-syscheckd' daemon and, it is combined with
                       the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple FIM events logs of the monitored directories.

    tags:
        - realtime
        - who_data
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Create the monitored directory with files and check that events are not raised
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file1', 'file2', 'file3'],
                     min_timeout=T_20, triggers_event=True, escaped=True)

    # Delete the directory
    os.rename(directory_str, f'{directory_str}_delete')
    shutil.rmtree(f'{directory_str}_delete', ignore_errors=True)
    time.sleep(5)

    # Re-create the directory
    os.makedirs(directory_str, exist_ok=True, mode=0o777)
    time.sleep(5)

    # Assert that events of new CUD actions are raised after next scheduled scan
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file4', 'file5', 'file6'],
                     min_timeout=T_20, triggers_event=True, escaped=True)
