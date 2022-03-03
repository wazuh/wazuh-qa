'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will verify that no FIM events are generated in the
       initial target of a 'symbolic link' when it has already been changed to the final target.
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
    modify_symlink, testdir_link, wait_for_symlink_check, testdir_target, testdir2
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
    extra_configuration_after_yield
from wazuh_testing import logger
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'yes'})
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply, previous_target, new_target', [
    ({'monitored_file'}, testdir1, os.path.join(testdir2, 'regular1')),
    ({'monitored_dir'}, testdir_target, testdir2)
])
def test_symbolic_change_target_inside_folder(tags_to_apply, previous_target, new_target, get_configuration,
                                              configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon stops detecting events when the target of a monitored symlink
                 is changed to a new folder. For this purpose, the test will monitor a 'symbolic link' pointing to
                 a file/folder. Once FIM starts, the test will change the target of the link to another file/folder
                 inside a monitored folder. Then, it will wait until the thread that checks the 'symbolic links'
                 updates the target of the link. Finally, it will generate some events inside the new target
                 and check that FIM events are triggered.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - previous_target:
            type: str
            brief: Directory where the 'symbolic link' is pointing.
        - new_target:
            type: str
            brief: Directory where the 'symbolic link' will be pointed after it is updated.
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
        - Verify that FIM events are generated at the initial target of the 'symbolic link'.
        - Verify that FIM events are generated at the final target of the 'symbolic link'.
        - Verify that no FIM events are generated in the initial target of the 'symbolic link'
          when it has already been changed to the final target.

    input_description: Two test cases (monitored_file and monitored_dir) are contained in external YAML file
                       (wazuh_conf.yaml) which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, these are combined with the testing directories to be monitored defined in
                       the 'common.py' module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'
    symlink = 'symlink' if tags_to_apply == {'monitored_file'} else 'symlink2'

    # Check create event if it's pointing to a directory
    if tags_to_apply == {'monitored_dir'}:
        fim.create_file(fim.REGULAR, previous_target, file1, content='')
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                error_message='Did not receive expected "Sending FIM event: ..." event')

    # Change the target to another file and wait the symcheck to update the link information
    modify_symlink(new_target, os.path.join(testdir_link, symlink))
    wait_for_symlink_check(wazuh_log_monitor)
    fim.wait_for_audit(whodata, wazuh_log_monitor)

    # Modify the content of the previous target and don't expect events. Modify the new target and expect an event
    fim.modify_file_content(previous_target, file1, new_content='Sample modification')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    fim.modify_file_content(testdir2, file1, new_content='Sample modification')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    modify = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()
    assert 'modified' in modify['data']['type'] and os.path.join(testdir2, file1) in modify['data']['path'], \
        f"'modified' event not matching for {testdir2} {file1}"
