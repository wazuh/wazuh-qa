# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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

@pytest.mark.parametrize('tags_to_apply, main_folder, aux_folder', [
    ({'monitored_file'}, testdir1, testdir_not_target),
    ({'monitored_dir'}, testdir_target, testdir_not_target)
])
def test_symbolic_delete_target(tags_to_apply, main_folder, aux_folder, get_configuration, configure_environment,
                                restart_syscheckd, wait_for_fim_start):
    """Check if syscheck detects events properly when removing a target, have the symlink updated and
    then recreating the target

    Having a symbolic link pointing to a file/folder, remove that file/folder and check that deleted event is
    detected.
    Once symlink_checker runs create the same file. No events should be raised. Wait again for symlink_checker run
    and modify the file. Modification event must be detected this time.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        main_folder (str): Directory that is being pointed at or contains the pointed file.
        aux_folder (str): Directory that will be pointed at or will contain the future pointed file.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If a expected event wasn't triggered.
        AttributeError: If a unexpected event was captured.
        ValueError: If the event's type and path are not the expected.
    """
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
