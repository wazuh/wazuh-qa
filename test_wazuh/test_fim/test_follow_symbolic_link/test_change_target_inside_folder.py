# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from test_fim.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_link, wait_for_symlink_check, wait_for_audit, test_directories, \
    extra_configuration_after_yield, extra_configuration_before_yield, testdir_target, testdir2
from wazuh_testing.fim import (generate_params, create_file, REGULAR, callback_detect_event,
                               check_time_travel, modify_file_content, LOG_FILE_PATH)
from wazuh_testing.tools import (check_apply_test,
                                 load_wazuh_configurations, FileMonitor)

# All tests in this module apply to linux only
pytestmark = pytest.mark.linux

# configurations

conf_params, conf_metadata = generate_params()
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

@pytest.mark.parametrize('tags_to_apply, previous_target, new_target', [
    ({'monitored_file'}, testdir1, os.path.join(testdir2, 'regular1')),
    ({'monitored_dir'}, testdir_target, testdir2)
])
def test_symbolic_change_target_inside_folder(tags_to_apply, previous_target, new_target, get_configuration,
                                              configure_environment, restart_syscheckd, wait_for_initial_scan):
    """ Check if syscheck stops detecting events from previous target when pointing to a new folder

    CHECK: Having a symbolic link pointing to a file/folder, change its target to another file/folder inside a monitored
    folder. After symlink_checker runs check that no events for the previous target file are detected while events for
    the new target are still being raised.

    :param previous_target: Previous symlink target (path)
    :param new_target: New symlink target (path)

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'
    symlink = 'symlink' if tags_to_apply == {'monitored_file'} else 'symlink2'

    # Check create event if it's pointing to a directory
    if tags_to_apply == {'monitored_dir'}:
        create_file(REGULAR, previous_target, file1, content='')
        check_time_travel(scheduled)
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)

    # Change the target to another file and wait the symcheck to update the link information
    modify_symlink(new_target, os.path.join(testdir_link, symlink))
    wait_for_symlink_check(wazuh_log_monitor)
    wait_for_audit(whodata, wazuh_log_monitor)

    # Modify the content of the previous target and don't expect events. Modify the new target and expect an event
    modify_file_content(previous_target, file1, new_content='Sample modification')
    check_time_travel(scheduled)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
    modify_file_content(testdir2, file1, new_content='Sample modification')
    check_time_travel(scheduled)
    modify = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    assert 'modified' in modify['data']['type'] and os.path.join(testdir2, file1) in modify['data']['path'], \
        f"'modified' event not matching for {testdir2} {file1}"
