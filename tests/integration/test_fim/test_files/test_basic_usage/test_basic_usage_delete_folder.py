'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if when a monitored folder is deleted,
       the files inside it generate FIM events of the type 'deleted'.
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
import shutil
from collections import Counter

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

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
directory_str = ','.join(test_directories)
for direc in list(test_directories):
    test_directories.append(os.path.join(direc, 'subdir'))
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories[2:]
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

@pytest.mark.parametrize('folder, file_list, filetype, tags_to_apply', [
    (testdir1, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},),
    (testdir2, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},)
])
@mark_skip_agentWindows
def test_delete_folder(folder, file_list, filetype, tags_to_apply,
                       get_configuration, configure_environment,
                       restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'deleted' events from the files contained
                 in a folder that is being deleted. For example, the folder '/testdir' is monitored, and
                 the files 'r1', 'r2' and 'r3' are inside '/testdir'. If '/testdir' is deleted, three
                 events of type 'deleted' must be generated, one for each of the regular files.
                 For this purpose, the test will monitor a folder using the 'scheduled' monitoring mode,
                 create the testing files inside it, and change the system time until the next
                 scheduled scan. Then, remove the monitored folder, and finally, the test
                 verifies that the 'deleted' events have been generated.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - folder:
            type: str
            brief: Path to the monitored testing directory.
        - file_list:
            type: list
            brief: Used names for the testing files.
        - filetype:
            type: str
            brief: Type of the testing file.
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
        - Verify that when a monitored folder is deleted, the files inside it
          generate FIM events of the type 'deleted'.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    mode = get_configuration['metadata']['fim_mode']

    # Create files inside subdir folder
    for file in file_list:
        create_file(filetype, folder, file, content='')

    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                     accum_results=len(file_list),
                                     error_message='Did not receive expected "Sending FIM event: ..." event').result()
    for ev in events:
        validate_event(ev, mode=mode)

    # Remove folder
    shutil.rmtree(folder, ignore_errors=True)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    # Expect deleted events
    event_list = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event',
                                         accum_results=len(file_list)).result()
    path_list = set([event['data']['path'] for event in event_list])
    counter_type = Counter([event['data']['type'] for event in event_list])
    for ev in events:
        validate_event(ev, mode=mode)

    assert counter_type['deleted'] == len(file_list), f'Number of "deleted" events should be {len(file_list)}'

    for file in file_list:
        assert os.path.join(folder, file) in path_list, f'File {file} not found within the events'
