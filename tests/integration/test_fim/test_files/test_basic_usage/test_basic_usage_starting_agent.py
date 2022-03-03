'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events of type 'modified' and
       'deleted' are generated when files that exist before starting the Wazuh agent are modified.
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
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, callback_detect_event, \
    create_file, generate_params, modify_file_content, check_time_travel, delete_file, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# Variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories
timeout = global_parameters.default_timeout
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")


# Extra functions
def extra_configuration_before_yield():
    # Create files before starting the service
    create_file(REGULAR, testdir1, 'regular0', content='')
    create_file(REGULAR, testdir1, 'regular1', content='')
    create_file(REGULAR, testdir1, 'regular2', content='')


# Configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('filename', [
    'regular0',
    'regular1',
    'regular2'
])
@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
@mark_skip_agentWindows
def test_events_from_existing_files(filename, tags_to_apply, get_configuration,
                                    configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects 'modified' and 'deleted' events when modifying
                 files that exist before the Wazuh agent is started. For this purpose, the test will modify
                 the testing file, change the system time to the next scheduled scan, and verify that
                 the proper FIM event is generated. Finally, the test will perform
                 the above steps but deleting the testing file.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - filename:
            type: str
            brief: Name of the testing file to be modified.
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
        - Verify that FIM events of type 'modified' and 'deleted' are generated
          when files that exist before starting the Wazuh agent are modified.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('modified' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    mode = get_configuration['metadata']['fim_mode']

    # Modify file
    modify_file_content(testdir1, filename, new_content='Sample content')

    # Expect modified event
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    modified_event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event,
                                             error_message='Did not receive expected '
                                                           '"Sending FIM event: ..." event').result()
    assert 'modified' in modified_event['data']['type'] and \
           os.path.join(testdir1, filename) in modified_event['data']['path']
    validate_event(modified_event, mode=mode)

    # Delete file
    delete_file(testdir1, filename)

    # Expect deleted event
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    deleted_event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()
    assert 'deleted' in deleted_event['data']['type'] and \
           os.path.join(testdir1, filename) in deleted_event['data']['path']
    validate_event(deleted_event, mode=mode)
