'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if the 'nodiff' tag works correctly
       when environment variables are used to define the files whose changes will not be tracked.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks  configured
       files for changes to the checksums, permissions, and ownership.

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
    - macos

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#diff

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
from test_fim.common import make_diff_file_path
from wazuh_testing import T_20, LOG_FILE_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.modules.fim.utils import regular_file_cud
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
test_folders = [os.path.join(PREFIX, 'testdir1'),
                os.path.join(PREFIX, 'testdir2')]
dir2 = test_folders[1]
dir_config = ",".join(test_folders)

# Check big environment variables ending with backslash
if sys.platform == 'win32':
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(10)] + [os.path.join(dir2, "test.txt")]
    test_env = "%TEST_NODIFF_ENV%"
else:
    paths = [os.path.join(PREFIX, 'a' * 50 + '\\') for i in range(100)] + [os.path.join(dir2, "test.txt")]
    test_env = "$TEST_NODIFF_ENV"

multiple_env_var = os.pathsep.join(paths)
environment_variables = [("TEST_NODIFF_ENV", multiple_env_var)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_nodiff.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_nodiff.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_ENV_VARIABLES'] = test_env
    configuration_parameters[count]['TEST_DIRECTORIES'] = dir_config
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


# Test
@pytest.mark.parametrize('test_folders', [test_folders], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_tag_nodiff(configuration, metadata, test_folders, set_wazuh_configuration, put_env_variables,
                    create_monitored_folders, configure_local_internal_options_function,
                    restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon truncates the content in the 'diff' files when testing files
                 are defined using environment variables via the 'nodiff' tag. For this purpose, the test will monitor
                 a directory using the 'report_changes=yes' attribute and some testing files will be defined in
                 the 'nodiff' tag using environment variables. Then, it will perform operations on the testing files
                 and check if the corresponding diff files have been created. Finally, the test will verify that
                 the 'diff' files of the testing files set in the 'nodiff' tag have their content truncated.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Set nodiff tag to be monitored in environment variables
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Create, Modify and Delete files in the monitored folder.
            - Check that report_changes data is shown or truncated when the file matches with the nodiff tag.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.2.0

    tier: 2

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
        - Verify that the 'content_changes' field of FIM events has a message
          indicating that the 'nodiff' option is being used.
        - Verify that 'diff' files are its content truncated when files are specified
          via environment variables using the 'nodiff' tag.

    input_description: The file 'configuration_nodiff.yaml' provides the configuration
                       template.
                       The file 'cases_nodiff.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)
        - The 'diff' file in the default location.

    tags:
        - scheduled
        - whodata
        - realtime
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    hidden_content = metadata['hidden_content']
    filename = metadata['filename']
    directory = test_folders[metadata['folder_id']]
    
    files = {filename: b'Hello word!'}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for file in files:
            diff_file = make_diff_file_path(directory, file)

            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if hidden_content:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                'content_changes is truncated'

    regular_file_cud(directory, wazuh_log_monitor, file_list=files, min_timeout=T_20, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator], escaped=True)
