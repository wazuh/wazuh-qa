# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
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
    """Check if syscheck stops detecting events from previous target when pointing to a new folder

    Having a symbolic link pointing to a file/folder, change its target to another file/folder inside a monitored
    folder. After symlink_checker runs check that no events for the previous target file are detected while events for
    the new target are still being raised.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        previous_target (str): Previous symlink target.
        new_target (str): New symlink target (path).
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
