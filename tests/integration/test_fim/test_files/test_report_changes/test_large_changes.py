'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM events include
       the 'content_changes' field with the tag 'More changes' when it exceeds the maximum size
       allowed, and the 'report_changes' option is enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_report_changes

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
    - fim_report_changes
'''
import gzip
import os
import shutil
import subprocess
import sys

import pytest
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import global_parameters, LOG_FILE_PATH, REGULAR
from wazuh_testing.modules.fim import TEST_DIR_1
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (callback_detect_event, get_fim_event, 
                                                     callback_detect_file_more_changes)
from wazuh_testing.modules.fim.utils import create_file
from test_fim.common import generate_string


# Marks
pytestmark = pytest.mark.tier(level=1)

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_large_changes.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_large_changes.yaml')

# Variables
test_directories = [os.path.join(PREFIX, TEST_DIR_1)]
testdir = test_directories[0]

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIRECTORIES'] = testdir
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)


# Tests
"""@pytest.mark.parametrize('filename, folder, original_size, modified_size', [
    ('regular_0', testdir, 500, 500),
    ('regular_1', testdir, 30000, 30000),
    ('regular_2', testdir, 70000, 70000),
    ('regular_3', testdir, 10, 20000),
    ('regular_4', testdir, 10, 70000),
    ('regular_5', testdir, 20000, 10),
    ('regular_6', testdir, 70000, 10),
])"""
@pytest.mark.parametrize('test_folders', [test_directories], scope="module", ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_large_changes(configuration, metadata, set_wazuh_configuration, configure_local_internal_options_function,
                        create_monitored_folders_module, restart_syscheck_function, wait_fim_start_function):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects the character limit in the file changes is reached
                 showing the 'More changes' tag in the 'content_changes' field of the generated events. For this
                 purpose, the test will monitor a directory, add a testing file and modify it, adding more characters
                 than the allowed limit. Then, it will unzip the 'diff' and get the size of the changes. Finally,
                 the test will verify that the generated FIM event contains in its 'content_changes' field the proper
                 value depending on the test case.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - filename:
            type: str
            brief: Name of the testing file to be created.
        - folder:
            type: str
            brief: Path to the directory where the testing files will be created.
        - original_size:
            type: int
            brief: Size of the testing file in bytes before being modified.
        - modified_size:
            type: int
            brief: Size of the testing file in bytes after being modified.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are generated when adding and modifying the testing file.
        - Verify that FIM events include the 'content_changes' field with the 'More changes' tag when
          the changes made on the testing file have more characters than the allowed limit.
        - Verify that FIM events include the 'content_changes' field with the old content
          of the monitored file.
        - Verify that FIM events include the 'content_changes' field with the new content
          of the monitored file when the old content is lower than the allowed limit or
          the testing platform is Windows.

    input_description: A test case (ossec_conf_report) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory and files to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)
        - The length of the testing file content by running the diff/fc command.
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    limit = 50000
    
    # Create the file and and capture the event.
    original_string = generate_string(metadata['original_size'], '0')
    create_file(REGULAR, testdir, metadata['filename'], content=original_string)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()

    # Modify the file with new content
    modified_string = generate_string(metadata['modified_size'], '1')
    create_file(REGULAR, testdir, metadata['filename'], content=modified_string)

    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()

    # Assert 'More changes' is shown when the command returns more than 'limit' characters
    if metadata['has_more_changes']:
        event = get_fim_event(timeout=global_parameters.default_timeout, callback=callback_detect_file_more_changes,
                              error_message='Did not find event with "More changes" within content_changes.')
    else:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()
        assert 'More changes' not in event['data']['content_changes'], '"More changes" found within content_changes.'

    # Assert old content is shown in content_changes
    assert '0' in event['data']['content_changes'], '"0" is the old value but it is not found within content_changes'

    # Assert new content is shown when old content is lower than the limit or platform is Windows
    if metadata['original_size'] < limit or sys.platform == 'win32':
        assert '1' in event['data']['content_changes'], '"1" is the new value but it is not found ' \
                                                        'within content_changes'
