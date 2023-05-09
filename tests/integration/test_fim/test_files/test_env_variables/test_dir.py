'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM events are
       generated when multiple environment variables are used to monitor directories.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_env_variables

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_env_variables
'''
import os
import sys

import pytest
from wazuh_testing import T_20, LOG_FILE_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.utils import regular_file_cud
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
test_folders = [os.path.join(PREFIX, 'testdir1'),
                os.path.join(PREFIX, 'testdir2'),
                os.path.join(PREFIX, 'testdir3'),
                os.path.join(PREFIX, 'testdir4')]
dir1, dir2, dir3, dir4 = test_folders

# Check big environment variables ending with backslash
if sys.platform == 'win32':
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(10)] + [dir2, dir3, dir4]
    test_env = "%TEST_ENV_ONE_PATH%, %TEST_ENV_MULTIPLES_PATH%"
else:
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(100)] + [dir2, dir3, dir4]
    test_env = "$TEST_ENV_ONE_PATH, $TEST_ENV_MULTIPLES_PATH"

multiple_env_var = os.pathsep.join(paths)
environment_variables = [("TEST_ENV_ONE_PATH", dir1), ("TEST_ENV_MULTIPLES_PATH", multiple_env_var)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_dir.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_dir.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_ENV_VARIABLES'] = test_env
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


#Test
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_tag_directories(configuration, metadata, test_folders, set_wazuh_configuration, put_env_variables,
                         create_monitored_folders, configure_local_internal_options_function,
                         restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects CUD events ('added', 'modified', and 'deleted')
                 when environment variables are used to monitor directories. For this purpose, the test
                 will monitor a directory that is defined in an environment variable. Then, different
                 operations will be performed on testing files, and finally, the test will verify
                 that the proper FIM events have been generated.


        test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Set folders to be monitored in environment variables
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Create, Modify and Delete files in the monitored folder.
            - Check events are generated as expected.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh


    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - directory:
            type: str
            brief: Path to the directory to be monitored.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - put_env_variables:
            type: fixture
            brief: Create the environment variables.
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
        - Verify that FIM events are generated when environment variables are used to monitor directories.

    input_description: The file 'configuration_dir.yaml' provides the configuration
                       template.
                       The file 'cases_dir.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - whodata
        - realtime
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    directory = test_folders[metadata['folder_id']]
    regular_file_cud(directory, wazuh_log_monitor, file_list=["testing_env_variables"], min_timeout=T_20, escaped=True)
