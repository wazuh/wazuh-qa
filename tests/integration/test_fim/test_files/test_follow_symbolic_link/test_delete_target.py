'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM stops detecting events when deleting
       the target of a monitored 'symbolic link'.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files for
       changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
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
    - macOS Catalina
    - Solaris 10
    - Solaris 11

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
    wait_for_symlink_check, testdir_target, testdir_not_target, delete_f
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

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply, main_folder, aux_folder', [
    ({'monitored_file'}, testdir1, testdir_not_target),
    ({'monitored_dir'}, testdir_target, testdir_not_target)
])
def test_symbolic_delete_target(tags_to_apply, main_folder, aux_folder, get_configuration, configure_environment,
                                restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events properly when deleting a target of a symlink,
                 this link is updated, and the target is recreated again. For this purpose, the test will monitor a
                 'symbolic link' pointing to a file/directory, and once FIM starts, it will create and expect events
                 inside the pointed folder. After the events are processed, the test will remove the link target and
                 wait until the links are reloaded. Then, the test will create the file/directory again, generate
                 events inside the target that the link was pointing to, and check that no FIM events are triggered.
                 Finally, the test will wait until the links are reloaded, generates, and checks the FIM events
                 with the updated link.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - main_folder:
            type: str
            brief: Directory that is being pointed at or contains the pointed file.
        - aux_folder:
            type: str
            brief: Directory that will be pointed at or will contain the future pointed file.
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
        - Verify that the FIM 'deleted' event is generated when deleting the target of the 'symbolic link'.
        - Verify that no FIM events are generated when the destination folder is restored,
          and the link information has not been updated yet.
        - Verify that the FIM 'modified' event is generated when the link information has been updated.

    input_description: Two test cases (monitored_file and monitored_dir) are contained in external YAML file
                       (wazuh_conf.yaml) which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, these are combined with the testing directories to be monitored defined in
                       the 'common.py' module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('modified' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'
    RELOAD_RULES_INTERVAL = 30

    # If symlink is pointing to a directory, we need to add files and expect their 'added' event (only if the file
    # is being created withing the pointed directory. Then, delete the pointed file or directory
    if tags_to_apply == {'monitored_dir'}:
        fim.create_file(fim.REGULAR, main_folder, file1, content='')
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                error_message='Did not receive expected "Sending FIM event: ..." event')
        delete_f(main_folder)
    else:
        delete_f(main_folder, file1)

    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    delete = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected "Sending FIM event: ..." event').result()
    assert 'deleted' in delete['data']['type'] and file1 in delete['data']['path'], \
        f"'deleted' event not matching for {file1}"

    if tags_to_apply == {'monitored_dir'} and whodata:
        wazuh_log_monitor.start(timeout=3, callback=fim.callback_audit_removed_rule,
                                error_message='Did not receive expected "Monitored directory \'{main_folder}\' was'
                                              'removed: Audit rule removed')
        os.makedirs(main_folder, exist_ok=True, mode=0o777)
        wazuh_log_monitor.start(timeout=RELOAD_RULES_INTERVAL, callback=fim.callback_audit_reloading_rules,
                                error_message='Did not receive expected "Reloading Audit rules" event')
        wazuh_log_monitor.start(timeout=RELOAD_RULES_INTERVAL, callback=fim.callback_audit_added_rule,
                                error_message='Did not receive expected "Added audit rule... '
                                '\'{main_folder}\'" event')
    else:
        # If syscheck is monitoring with whodata, wait for audit to reload rules
        fim.wait_for_audit(whodata, wazuh_log_monitor)
        wait_for_symlink_check(wazuh_log_monitor)

    # Restore the target
    fim.create_file(fim.REGULAR, main_folder, file1, content='')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if tags_to_apply == {'monitored_dir'} and whodata:
        wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                error_message='Did not receive expected "Sending FIM event: ..." event')
    else:
        # We don't expect any event since symlink hasn't updated the link information
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event)
            logger.error('A "Sending FIM event: ..." event has been detected. No event should be detected as symlink '
                         'has not updated the link information yet.')
            logger.error(f'Unexpected event {event.result()}')
            raise AttributeError(f'Unexpected event {event.result()}')

    wait_for_symlink_check(wazuh_log_monitor)
    fim.wait_for_audit(whodata, wazuh_log_monitor)

    # Modify the files and expect events since symcheck has updated now
    fim.modify_file_content(main_folder, file1, 'Sample modification')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    modify = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected "Sending FIM event: ..." event').result()
    assert 'modified' in modify['data']['type'] and file1 in modify['data']['path'], \
        f"'modified' event not matching for {file1}"
