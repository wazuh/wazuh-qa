'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. All these tests will be performed using ambiguous directory configurations,
       such as directories and subdirectories with opposite monitoring settings. In particular, it
       will be verified that the value of the 'ignore' attribute prevails over the 'restrict' one.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_ambiguous_complex

targets:
    - agent

daemons:
    - wazuh-agentd
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
    - fim_ambiguous_confs
'''
import os
import sys

import pytest
from wazuh_testing import LOG_FILE_PATH, REGULAR, T_10
from wazuh_testing.tools import PREFIX
from wazuh_testing.modules.fim.event_monitor import CB_IGNORING_DUE_TO_SREGEX, CB_IGNORING_DUE_TO_PATTERN
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.file import create_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

# Configurations
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_templates')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_ignore_works_over_restrict.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_ignore_works_over_restrict.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIR1'] = test_directories[0]
    configuration_parameters[count]['TEST_DIR2'] = test_directories[1]
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

"""
# TODO Tests to move to new framework
@pytest.mark.parametrize('folder, filename, triggers_event, tags_to_apply', [
    (testdir1, 'testfile', False, {'valid_no_regex'}),
    (testdir1, 'testfile2', False, {'valid_regex'}),
    (testdir1, 'ignore_testfile2', False, {'valid_regex'}),
])
"""

@pytest.mark.parametrize('test_folders', [test_directories], scope="module", ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_ignore_works_over_restrict(configuration, metadata, set_wazuh_configuration, test_folders,
                                        create_monitored_folders_module, configure_local_internal_options_function,
                                        restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if the 'ignore' tag prevails over the 'restrict' one when using both in the same directory.
                 For example, when a directory is ignored and at the same time monitoring is restricted to a file
                 that is in that directory, no FIM events should be generated when that file is modified.
                 For this purpose, the test case configuration is applied, and it is checked if FIM events
                 are generated when required.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - folder:
            type: str
            brief: Directory where the file is being created.
        - filename:
            type: str
            brief: Name of the file to be created.
        - triggers_event:
            type: bool
            brief: True if an event must be generated, False otherwise.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that when a directory is ignored, the 'restrict' attribute
          is not taken into account to generate FIM events.

    input_description: Two test cases are contained in external YAML file
                       (wazuh_conf_ignore_restrict.yaml or wazuh_conf_ignore_restrict_win32.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and testing directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (When the FIM event should be generated)
        - r".*Ignoring '.*?' '(.*?)' due to (sregex|pattern)? '.*?'" (When the FIM event should be ignored)

    tags:
        - scheduled
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    folder = test_directories[metadata['folder']]
    filename = metadata['filename']
    
    # Create file that must be ignored
    create_file(REGULAR, folder, filename, content='')

    regex = CB_IGNORING_DUE_TO_PATTERN if metadata['is_pattern'] else CB_IGNORING_DUE_TO_SREGEX
    matching_log = wazuh_log_monitor.start(timeout=T_10,
                                               accum_results=2,
                                               callback=generate_monitoring_callback(regex),
                                               error_message=f'Did not receive expected '
                                                             f'"Ignoring ... due to ..." event for file '
                                                             f'{os.path.join(folder, filename)}').result()

    assert os.path.join(folder, filename) in matching_log, "Ignored file log is not generated."
