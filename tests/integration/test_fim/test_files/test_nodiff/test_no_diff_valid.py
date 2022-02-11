'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM ignores the modifications made
       in a monitored file when it matches the 'nodiff' tag and vice versa.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP
    - macOS Catalina

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
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
    - fim_nodiff
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, WAZUH_PATH, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=2)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path,
                                   'wazuh_conf_win32.yaml' if sys.platform == 'win32' else 'wazuh_conf.yaml')

test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir1', 'subdir'),
                    os.path.join(PREFIX, 'testdir1', 'ignore_this'),
                    os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_nodiff, testdir2, testdir2_sub = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params()

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('folder, filename, content, hidden_content, tags_to_apply', [
    (testdir1, 'testfile', "Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'btestfile', b"Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'testfile2', "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2.nodiff", b"", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir1, "btestfile2.nodiffd", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile', "Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'btestfile', b"Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile2', "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, "btestfile2", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, ".nodiff.btestfile", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.nodiff", b"other content", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2, "another.nodiffd", b"other content", False, {'valid_regex'}),
    (testdir2_sub, "another.nodiff", b"other content", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2_sub, "another.nodiffd", b"other content", False, {'valid_regex'}),
    (testdir2, "another.nodiffd2", "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.nodiff2", "", True, {'valid_regex2', 'valid_regex3'}),
    (testdir1, 'nodiff_prefix_test.txt', "test", False,
     {'valid_regex1', 'valid_regex2', 'valid_regex3', 'valid_regex4'}),
    (testdir1, 'nodiff_prefix_test.txt', "test", True, {'valid_regex5'}),
    (testdir1, 'whatever.txt', "test", True, {'valid_empty'}),
    (testdir2, 'whatever2.txt', "test", True, {'valid_empty'})
])
def test_no_diff_subdirectory(folder, filename, content, hidden_content,
                              tags_to_apply, get_configuration,
                              configure_environment, restart_syscheckd,
                              wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon truncates the file changes in the generated events using
                 the 'nodiff' tag and vice versa. For this purpose, the test will monitor a directory or subdirectory
                 and make file operations inside it. Then, it will check if the 'diff' file is created for each
                 testing file modified. Finally, if the testing files match the 'nodiff' tag, the test will verify
                 that the FIM events generated contain in their 'content_changes' field a message indicating that
                 'diff' is truncated because the 'nodiff' option is used.

    wazuh_min_version: 4.2.0

    parameters:
        - folder:
            type: str
            brief: Path to the directory where the testing file will be created.
        - filename:
            type: str
            brief: Name of the testing file to be created.
        - content:
            type: str
            brief: Content to fill the testing file.
        - hidden_content:
            type: bool
            brief: True if the content of the testing file must be truncated. False otherwise.
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
        - Verify that FIM ignores the modifications made in a monitored file
          when it matches the 'nodiff' tag.
        - Verify that FIM includes the modifications made in a monitored file
          when it does not match the 'nodiff' tag.

    input_description: Diferent test cases are contained in external YAML files
                       (wazuh_conf.yaml or wazuh_conf_win32.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and,
                       these are combined with the testing directories
                       to be monitored defined in the module.

    inputs:
        - 567 test cases including multiple regular expressions and names for testing files and directories.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    files = {filename: content}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for file in files:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')

            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')

            striped = folder.strip(os.sep) if sys.platform == 'darwin' else folder.strip(PREFIX)
            diff_file = os.path.join(diff_file, striped, file)

            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, f'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if hidden_content:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                f'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                f'content_changes is truncated'

    regular_file_cud(folder, wazuh_log_monitor, file_list=files,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator])
