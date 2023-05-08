# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from subprocess import Popen, PIPE, DEVNULL
import re
import pytest

from wazuh_testing import global_parameters, LOG_FILE_PATH, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.file import create_file
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import (callback_detect_event, callback_detect_file_deleted_event,
                                                     ERR_MSG_FIM_EVENT_NOT_RECIEVED)
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# variables
test_folders = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir1', 'subdir')]
directory_str = ','.join(test_folders)

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_basic_usage_deferred_delete_folder.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_basic_usage_win32.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = directory_str
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_deferred_delete_file(configuration, metadata, test_folders, set_wazuh_configuration,
                              create_monitored_folders_module, configure_local_internal_options_function,
                              restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if syscheckd detects 'deleted' events from the files contained in a folder that are deleted in a
                 deferred manner. We first run the command in order to find the confirmation character in the os, after
                 that we delete the files

        test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Create files inside the folder.
            - Use the command 'del' to delete the files.
            - Check that deleted events are generated as expected.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

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
        - Verify that FIM events of type 'modified' and 'deleted' are generated
          when files that exist before starting the Wazuh agent are modified.


    input_description: The file 'configuration_basic_usage.yaml' provides the configuration
                       template.
                       The file 'cases_basic_usage_move_dir.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('modified' and 'deleted' events)

    tags:

        - whodata
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    folder = test_folders[0]
    file_list = ['regular0', 'regular1', 'regular2']
    filetype = REGULAR    

    # Create files inside subdir folder
    for file in file_list:
        create_file(filetype, folder, file, content='')

    # Wait for the added events
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            accum_results=len(file_list), error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED)

    # Delete the files under 'folder'
    command = 'del "{}"\n'.format(folder)

    cmd = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    try:
        stdout = cmd.communicate(timeout=global_parameters.default_timeout)
    except TimeoutError:
        pass

    # Find the windows confirmation character
    confirmation = re.search(r'\((\w)\/\w\)\?', stdout[0])
    assert confirmation

    # Run the command again and confirm deletion of files
    cmd = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    try:
        stdout = cmd.communicate('{}\n'.format(confirmation.group(1)), timeout=global_parameters.default_timeout)
    except TimeoutError:
        pass

    # Start monitoring
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_file_deleted_event,
                            accum_results=len(file_list), error_message=ERR_MSG_FIM_EVENT_NOT_RECIEVED)
