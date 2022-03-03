'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events of type 'added' and 'deleted'
       are generated when monitored directories or files are renamed.
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

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
for direc in list(test_directories):
    test_directories.append(os.path.join(direc, 'subdir'))
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories[2:]
new_name = 'this_is_a_new_name'
old_name = 'old_name'

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def clean_directories(request):
    renamed_dir = os.path.join(PREFIX, getattr(request.module, 'new_name'))
    directories = getattr(request.module, 'test_directories')[0:2]
    directories.append(renamed_dir)
    for test_dir in directories:
        shutil.rmtree(test_dir, ignore_errors=True)
    yield
    shutil.rmtree(renamed_dir, ignore_errors=True)


# tests

@pytest.mark.parametrize('folder, tags_to_apply', [
    (testdir1, {'ossec_conf'}),
    (testdir2, {'ossec_conf'})
])
def test_rename(folder, tags_to_apply,
                get_configuration, clean_directories, configure_environment,
                restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when renaming directories or files.
                 When changing directory or file names, FIM events of type 'deleted' and 'added'
                 should be generated. For this purpose, the test will create the directory and testing files
                 to be monitored and verify that they have been created correctly. It will then verify two cases,
                 on the one hand that the proper FIM events are generated when the testing files are renamed
                 in the monitored directory, and on the other hand, that these events are generated
                 when the monitored directory itself is renamed.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - folder:
            type: str
            brief: Path to the directory where the files will be created.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - clean_directories:
            type: fixture
            brief: Delete the contents of the testing directory.
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
        - Verify that FIM events of type 'added' and 'deleted' are generated
          when monitored directories or files are renamed.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    def expect_events(path):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        try:
            assert 'added' in event['data']['type'] and path in event['data']['path'], \
                f'Deleted event not detected'
        except AssertionError:
            if 'deleted' not in event['data']['type'] and new_name not in event['data']['path']:
                raise AssertionError(f'Wrong event when renaming a non empty directory')

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    mode = get_configuration['metadata']['fim_mode']

    create_file(REGULAR, folder, old_name, content='')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                    error_message='Did not receive expected "Sending FIM event: ..." event').result()
    validate_event(event, mode=mode)

    # testdir1 will have renamed files within. testdir2 will be renamed with files within
    if folder == testdir1:
        # Change the file name
        os.rename(os.path.join(folder, old_name), os.path.join(folder, new_name))
        check_time_travel(scheduled, monitor=wazuh_log_monitor)
        # Expect deleted and created events
        deleted = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=callback_detect_event,
                                          error_message='Did not receive expected '
                                                        '"Sending FIM event: ..." event'
                                          ).result()
        try:
            assert 'deleted' in deleted['data']['type'] and os.path.join(folder, old_name) in deleted['data']['path']
        except AssertionError:
            if 'added' not in deleted['data']['type'] and os.path.join(folder, old_name) not in deleted['data']['path']:
                raise AssertionError(f'Wrong event when renaming a file')
        validate_event(deleted, mode=mode)

        added = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        try:
            assert 'added' in added['data']['type'] and os.path.join(folder, new_name) in added['data']['path']
        except AssertionError:
            if 'deleted' not in added['data']['type'] and os.path.join(folder, new_name) not in added['data']['path']:
                raise AssertionError(f'Wrong event when renaming a file')
        validate_event(added, mode=mode)
    else:
        os.rename(folder, os.path.join(os.path.dirname(folder), new_name))
        check_time_travel(scheduled, monitor=wazuh_log_monitor)
        expect_events(new_name)
        expect_events(folder)
