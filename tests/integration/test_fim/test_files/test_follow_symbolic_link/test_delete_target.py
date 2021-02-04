# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    wait_for_symlink_check, wait_for_audit, testdir_target, testdir_not_target, delete_f
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
    extra_configuration_after_yield
from wazuh_testing import logger
from wazuh_testing.fim import generate_params, create_file, REGULAR, callback_detect_event, \
    callback_audit_removed_rule, callback_audit_reloaded_rule, callback_audit_reloading_rules, check_time_travel, \
    modify_file_content, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# configurations

conf_params, conf_metadata = generate_params(extra_params={'FOLLOW_MODE': 'yes'})
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


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
    """
    Check if syscheck detects events properly when removing a target, have the symlink updated and
    then recreating the target

    CHECK: Having a symbolic link pointing to a file/folder, remove that file/folder and check that deleted event is
    detected.
    Once symlink_checker runs create the same file. No events should be raised. Wait again for symlink_checker run
    and modify the file. Modification event must be detected this time.

    Parameters
    ----------
    main_folder : str
        Directory that is being pointed at or contains the pointed file.
    aux_folder : str
        Directory that will be pointed at or will contain the future pointed file.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'
    RELOAD_RULES_INTERVAL = 30

    # If symlink is pointing to a directory, we need to add files and expect their 'added' event (only if the file
    # is being created withing the pointed directory. Then, delete the pointed file or directory
    if tags_to_apply == {'monitored_dir'}:
        create_file(REGULAR, main_folder, file1, content='')
        check_time_travel(scheduled, monitor=wazuh_log_monitor)
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_event,
                                error_message='Did not receive expected "Sending FIM event: ..." event')
        delete_f(main_folder)
    else:
        delete_f(main_folder, file1)

    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    delete = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event,
                                     error_message='Did not receive expected "Sending FIM event: ..." event').result()
    assert 'deleted' in delete['data']['type'] and file1 in delete['data']['path'], \
        f"'deleted' event not matching for {file1}"

    if tags_to_apply == {'monitored_dir'} and whodata:
        os.makedirs(main_folder, exist_ok=True, mode=0o777)
        wazuh_log_monitor.start(timeout=3, callback=callback_audit_removed_rule,
                                error_message='Did not receive expected "Monitored directory \'{main_folder}\' was'
                                              'removed: Audit rule removed')
        wazuh_log_monitor.start(timeout=RELOAD_RULES_INTERVAL, callback=callback_audit_reloading_rules,
                                error_message='Did not receive expected "Reloading Audit rules" event')
        wazuh_log_monitor.start(timeout=RELOAD_RULES_INTERVAL, callback=callback_audit_reloaded_rule,
                                error_message='Did not receive expected "Reloaded audit rule for monitoring directory: '
                                              '\'{main_folder}\'" event')
    else:
        # If syscheck is monitoring with whodata, wait for audit to reload rules
        wait_for_audit(whodata, wazuh_log_monitor)
        wait_for_symlink_check(wazuh_log_monitor)

    # Restore the target
    create_file(REGULAR, main_folder, file1, content='')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if tags_to_apply == {'monitored_dir'} and whodata:
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_event,
                                error_message='Did not receive expected "Sending FIM event: ..." event')
    else:
        # We don't expect any event since symlink hasn't updated the link information
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
            logger.error('A "Sending FIM event: ..." event has been detected. No event should be detected as symlink '
                         'has not updated the link information yet.')
            logger.error(f'Unexpected event {event.result()}')
            raise AttributeError(f'Unexpected event {event.result()}')

    wait_for_symlink_check(wazuh_log_monitor)
    wait_for_audit(whodata, wazuh_log_monitor)

    # Modify the files and expect events since symcheck has updated now
    modify_file_content(main_folder, file1, 'Sample modification')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    modify = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event,
                                     error_message='Did not receive expected "Sending FIM event: ..." event').result()
    assert 'modified' in modify['data']['type'] and file1 in modify['data']['path'], \
        f"'modified' event not matching for {file1}"
