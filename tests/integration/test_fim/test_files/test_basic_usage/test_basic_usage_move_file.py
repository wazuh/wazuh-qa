'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events are generated when files
       are moved between monitored directories.
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
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel, delete_file, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir1', 'subdir')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2, testdir1_subdir = test_directories
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests


@pytest.mark.parametrize('file, file_content, tags_to_apply', [
    ('regular1', '', {'ossec_conf'})
])
@pytest.mark.parametrize('source_folder, target_folder, triggers_delete_event, triggers_add_event', [
    (testdir1, PREFIX, True, False),
    (testdir1, testdir1_subdir, True, True),
    (testdir1, testdir2, True, True),
    (PREFIX, testdir1, False, True),
    (PREFIX, testdir1_subdir, False, True)
])
@mark_skip_agentWindows
def test_move_file(file, file_content, tags_to_apply, source_folder, target_folder,
                   triggers_delete_event, triggers_add_event,
                   get_configuration, configure_environment,
                   restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'added' and 'deleted' events when moving a file
                 from a monitored folder to another one. For this purpose, the test will create a testing file and
                 move it from the source directory to the target directory. Then, it changes the system time until
                 the next scheduled scan, and finally, it removes the testing file and verifies that
                 the expected FIM events have been generated.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - file:
            type: str
            brief: Name of the testing file to be created.
        - file_content:
            type: str
            brief: Content of the testing file to be created.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - source_folder:
            type: str
            brief: Path to the source directory where the testing file to move is located.
        - target_folder:
            type: str
            brief: Path to the destination directory where the testing file will be moved.
        - triggers_delete_event:
            type: bool
            brief: True if it expects a 'deleted' event in the source folder. False otherwise.
        - triggers_add_event:
            type: bool
            brief: True if it expects an 'added' event in the target folder. False otherwise.
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
        - Verify that FIM events of type 'added' and 'deleted' are generated
          when files are moved between monitored directories.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    mode = get_configuration['metadata']['fim_mode']

    # Create file inside folder
    create_file(REGULAR, source_folder, file, content=file_content)

    if source_folder in test_directories:
        check_time_travel(scheduled, monitor=wazuh_log_monitor)
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                        error_message='Did not receive expected "Sending FIM event: .." event').result()
        validate_event(event, mode=mode)

    # Move file to target directory
    os.rename(os.path.join(source_folder, file), os.path.join(target_folder, file))
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    # Monitor expected events
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     accum_results=(triggers_add_event + triggers_delete_event),
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()

    # Expect deleted events
    if isinstance(events, list):
        events_data = [(event['data']['type'],
                        event['data']['path'],
                        os.path.join(source_folder, file) if event['data']['type'] == 'deleted' else os.path.join(
                            target_folder, file))
                       for event in events]
        assert set([event[0] for event in events_data]) == {'deleted', 'added'}
        for _, path, expected_path in events_data:
            assert path == expected_path
    else:
        if triggers_delete_event:
            assert 'deleted' in events['data']['type'] and os.path.join(source_folder, file) in events['data']['path']
        else:
            assert 'added' in events['data']['type'] and os.path.join(target_folder, file) in events['data']['path']

    events = [events] if not isinstance(events, list) else events
    for ev in events:
        validate_event(ev, mode=mode)

    # Remove file
    delete_file(target_folder, file)
    if target_folder in test_directories:
        check_time_travel(scheduled, monitor=wazuh_log_monitor)
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                        error_message='Did not receive expected "Sending FIM event: .." event').result()
        validate_event(event, mode=mode)
