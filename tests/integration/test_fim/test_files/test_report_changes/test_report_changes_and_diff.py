'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM reports (or truncates if required)
       the changes made in monitored files when it matches the 'nodiff' tag and vice versa when
       the 'report_changes' option is enabled.
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#nodiff

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
import os
import re
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, regular_file_cud, WAZUH_PATH, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir_reports'), os.path.join(PREFIX, 'testdir_nodiff')]
nodiff_file = os.path.join(PREFIX, 'testdir_nodiff', 'regular_file')

directory_str = ','.join(test_directories)
testdir_reports, testdir_nodiff = test_directories
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'NODIFF_FILE': nodiff_file,
                                                           'MODULE_NAME': __name__})

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_report'}
])
@pytest.mark.parametrize('folder, checkers', [
    (testdir_reports, options),
    (testdir_nodiff, options)
])
@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_reports_file_and_nodiff(folder, checkers, tags_to_apply,
                                 get_configuration, configure_environment,
                                 restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon reports the file changes (or truncates if required)
                 in the generated events using the 'nodiff' tag and vice versa. For this purpose, the test
                 will monitor a directory and make file operations inside it. Then, it will check if a
                 'diff' file is created for the modified testing file. Finally, if the testing file matches
                 the 'nodiff' tag, the test will verify that the FIM event generated contains in its
                 'content_changes' field a message indicating that 'diff' is truncated because
                 the 'nodiff' option is used.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - folder:
            type: str
            brief: Path to the directory where the testing files will be created.
        - checkers:
            type: dict
            brief: Syscheck 'check_' fields to be generated.
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
        - Verify that for each modified file a 'diff' file is generated.
        - Verify that FIM events include the 'content_changes' field.
        - Verify that FIM events truncate the modifications made in a monitored file
          when it matches the 'nodiff' tag.
        - Verify that FIM events include the modifications made in a monitored file
          when it does not match the 'nodiff' tag.

    input_description: A test case (ossec_conf_report) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - diff
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file_list = ['regular_file']
    is_truncated = folder == testdir_nodiff

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
                diff_file = os.path.join(diff_file, re.match(r'^[a-zA-Z]:(\\){1,2}(\w+)(\\){0,2}$', folder).group(2),
                                         file)
            else:
                diff_file = os.path.join(diff_file, folder.strip('/'), file)
            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, f'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if is_truncated:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                f'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                f'content_changes is truncated'

    regular_file_cud(folder, wazuh_log_monitor, file_list=file_list,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator])
