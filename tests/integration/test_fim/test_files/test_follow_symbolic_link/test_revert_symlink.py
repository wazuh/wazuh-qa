'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM monitors the target
       of a 'symbolic link' when it is changed and when that change is reverted.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_follow_symbolic_link

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - macos
    - solaris

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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_follow_symbolic_link
'''
import os

import pytest
import wazuh_testing.fim as fim

from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_link, wait_for_symlink_check
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
    extra_configuration_after_yield
from wazuh_testing import logger
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'yes'})
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
    {'monitored_file'}
])
def test_symbolic_revert_symlink(tags_to_apply, get_configuration, configure_environment,
                                 restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects new targets when monitoring a directory with
                 a symlink and its target is changed. For this purpose, the test will create a 'symbolic link'
                 to a file/directory. Then, it will change the target to a directory and create some files
                 inside, expecting all the FIM events. After the events are processed, the test will change
                 the link to its previous target, and finally, it will make file operations and expect FIM events.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
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
        - Verify that FIM events are generated when a monitored 'symbolic link' target
          is changed to a new directory.
        - Verify that FIM events are generated when a monitored 'symbolic link' target
          is reverted to the previous directory.

    input_description: A test case (monitored_file) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these  are combined
                       with the testing directories to be monitored defined in the common.py module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - time_travel
    '''
    def modify_and_assert(file):
        fim.modify_file_content(testdir1, file, new_content='Sample modification')
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        ev = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event).result()
        assert 'modified' in ev['data']['type'] and os.path.join(testdir1, file) in ev['data']['path'], \
            f"'modified' event not matching for {testdir1} {file}"

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'
    file2 = 'regular2'

    # Don't expect an event since it is not being monitored yet
    fim.modify_file_content(testdir1, file2, new_content='Sample modification')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Change the target to the folder and now expect an event
    modify_symlink(testdir1, os.path.join(testdir_link, 'symlink'))
    wait_for_symlink_check(wazuh_log_monitor)
    fim.wait_for_audit(whodata, wazuh_log_monitor)
    modify_and_assert(file2)

    # Modify symlink target, wait for sym_check to update it
    modify_symlink(os.path.join(testdir1, file1), os.path.join(testdir_link, 'symlink'))
    wait_for_symlink_check(wazuh_log_monitor)
    # Wait for audit to reload the rules
    fim.wait_for_audit(whodata, wazuh_log_monitor)

    fim.modify_file_content(testdir1, file2, new_content='Sample modification2')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')
    modify_and_assert(file1)
