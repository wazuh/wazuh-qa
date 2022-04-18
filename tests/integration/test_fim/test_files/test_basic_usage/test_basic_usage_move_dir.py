'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM events are generated
       when subfolders are moved between monitored directories.
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
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2, testdir3 = test_directories
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")


# This directory won't be monitored
testdir4 = os.path.join(PREFIX, 'testdir4')

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


def extra_configuration_before_yield():
    """Create subdirs before restarting Wazuh."""
    create_file(REGULAR, os.path.join(testdir1, 'subdir'), 'regular1', content='')
    create_file(REGULAR, os.path.join(testdir3, 'subdir2'), 'regular2', content='')
    create_file(REGULAR, os.path.join(testdir3, 'subdir3'), 'regular3', content='')
    create_file(REGULAR, os.path.join(testdir4, 'subdir'), 'regular1', content='')


def extra_configuration_after_yield():
    """Delete subdir directory after finishing the module execution since it's not monitored."""
    shutil.rmtree(os.path.join(PREFIX, 'subdir'), ignore_errors=True)
    shutil.rmtree(testdir4, ignore_errors=True)


@pytest.mark.parametrize('source_folder, target_folder, subdir, tags_to_apply, \
                triggers_delete_event, triggers_add_event', [
    (testdir4, testdir2, 'subdir', {'ossec_conf'}, False, True),
    (testdir1, PREFIX, 'subdir', {'ossec_conf'}, True, False),
    (testdir3, testdir2, 'subdir2', {'ossec_conf'}, True, True),
    (testdir3, testdir2, f'subdir3{os.path.sep}', {'ossec_conf'}, True, True)
])
@mark_skip_agentWindows
def test_move_dir(source_folder, target_folder, subdir, tags_to_apply, triggers_delete_event, triggers_add_event,
                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'added' and 'deleted' events when moving a subdirectory
                 from a monitored folder to another one. For this purpose, the test will move a testing subfolder
                 from the source directory to the target directory and change the system time until the next
                 scheduled scan. Finally, it verifies that the expected FIM events have been generated.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - source_folder:
            type: str
            brief: Path to the source directory where the subfolder to move is located.
        - target_folder:
            type: str
            brief: Path to the destination directory where the subfolder will be moved.
        - subdir:
            type: str
            brief: Name of the subfolder to be moved.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
          when subfolders are moved between monitored directories.

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

    if mode == 'whodata' and subdir[-1] == os.path.sep and sys.platform == 'linux':
        pytest.xfail('Xfailing due to issue: https://github.com/wazuh/wazuh/issues/4720')
    elif mode == 'whodata' and subdir[-1] == os.path.sep and sys.platform == 'win32':
        pytest.xfail('Xfailing due to issue: https://github.com/wazuh/wazuh/issues/6089')

    # Move folder to target directory
    os.rename(os.path.join(source_folder, subdir), os.path.join(target_folder, subdir))
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    # Monitor expected events
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     accum_results=(triggers_add_event + triggers_delete_event),
                                     error_message='Did not receive expected "Sending FIM event: ..." event'
                                     ).result()

    # Expect deleted events
    if isinstance(events, list):
        events_data = [(event['data']['type'],
                        os.path.dirname(event['data']['path']),
                        os.path.join(source_folder, subdir) if event['data']['type'] == 'deleted' else os.path.join(
                            target_folder, subdir))
                       for event in events]
        assert set([event[0] for event in events_data]) == {'deleted', 'added'}
        for _, path, expected_path in events_data:
            assert path == expected_path.rstrip(os.path.sep)
    else:
        if triggers_delete_event:
            assert 'deleted' in events['data']['type'] and os.path.join(source_folder, subdir) \
                   in os.path.dirname(events['data']['path'])
        if triggers_add_event:
            assert 'added' in events['data']['type'] and os.path.join(target_folder, subdir) \
                   in os.path.dirname(events['data']['path'])

    events = [events] if not isinstance(events, list) else events
    for ev in events:
        validate_event(ev, mode=mode)
