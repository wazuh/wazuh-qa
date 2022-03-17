'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM ignores the elements
       set in the 'ignore' option using both regex and regular names for specifying them.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_ignore

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#ignore

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_ignore
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, callback_ignore, create_file, REGULAR, \
    generate_params, check_time_travel
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
                    os.path.join(PREFIX, 'testdir1', 'folder'),
                    os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_ignore, testdir1_ignore_folder, testdir2, testdir2_sub = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params()

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('folder, filename, content, triggers_event, tags_to_apply', [
    (testdir1, 'testfile', "Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'btestfile', b"Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'testfile2', "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2.ignore", b"", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir1, "btestfile2.ignored", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile', "Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'btestfile', b"Sample content", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile2', "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, "btestfile2", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, ".ignore.btestfile", b"", True, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.ignore", b"other content", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2, "another.ignored", b"other content", True, {'valid_regex'}),
    (testdir2_sub, "another.ignore", b"other content", False, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2_sub, "another.ignored", b"other content", True, {'valid_regex'}),
    (testdir2, "another.ignored2", "", True, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.ignore2", "", False, {'valid_regex2', 'valid_regex3'}),
    (testdir1, 'ignore_prefix_test.txt', "test", True,
     {'valid_regex1', 'valid_regex2', 'valid_regex3', 'valid_regex4'}),
    (testdir1, 'ignore_prefix_test.txt', "test", False, {'valid_regex5'}),
    (testdir1, 'whatever.txt', "test", False, {'valid_empty'}),
    (testdir2, 'whatever2.txt', "test", False, {'valid_empty'}),
    (testdir1, 'mytest', "test", True, {'negation_regex'}),
    (testdir1, 'othername', "test", False, {'negation_regex'}),
    (testdir1, 'file1', "test", False, {'incomplete_regex'}),
    (testdir1_ignore_folder, 'file2', "test", False, {'incomplete_regex'}),
    (testdir1, 'file1', "test", False, {'ignore_disk'})
])
@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_ignore_subdirectory(folder, filename, content, triggers_event,
                             tags_to_apply, get_configuration,
                             configure_environment, restart_syscheckd,
                             wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon ignores the files that are in a monitored subdirectory
                 when using the 'ignore' option. It also ensures that events for files tha are not being ignored
                 are still detected. For this purpose, the test will monitor folders containing files to be ignored
                 using names or regular expressions. Then it will create these files and check if FIM events should
                 be generated. Finally, the test will verify that the generated FIM events correspond to the files
                 that must not be ignored.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - folder:
            type: set
            brief: Path to the directory where the file is being created.
        - filename:
            type: set
            brief: Name of the file to be created.
        - content:
            type: set
            brief: Content to fill the new file.
        - triggers_event:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - checkers:
            type: dict
            brief: Check options to be used.
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
        - Verify that FIM 'ignore' events are generated for each ignored element.
        - Verify that FIM 'added' events are generated for files
          that do not match the value of the 'ignore' option.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_conf.yaml or wazuh_conf_win32.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, these are combined with the testing directories
                       to be monitored defined in the module.

    inputs:
        - 936 test cases including multiple regular expressions and names for testing files and directories.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*Ignoring .* due to'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create text files
    create_file(REGULAR, folder, filename, content=content)

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 2,
                                        callback=callback_detect_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        assert event['data']['type'] == 'added', 'Event type not equal'
        assert event['data']['path'] == os.path.join(folder, filename), 'Event path not equal'
    else:
        while True:
            ignored_file = wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 2,
                                                   callback=callback_ignore).result()
            if ignored_file == os.path.join(folder, filename):
                break
