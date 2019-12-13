# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from test_fim.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_link, wait_for_symlink_check, wait_for_audit, test_directories, \
    extra_configuration_after_yield, extra_configuration_before_yield, testdir_target, testdir_not_target
from wazuh_testing.fim import (generate_params, create_file, REGULAR, callback_detect_event,
                               check_time_travel, modify_file_content, LOG_FILE_PATH)
from wazuh_testing.tools import (check_apply_test,
                                 load_wazuh_configurations, FileMonitor)

# All tests in this module apply to linux only
pytestmark = pytest.mark.linux

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params()
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

@pytest.mark.parametrize('tags_to_apply, main_folder, aux_folder', [
    ({'monitored_file'}, testdir1, testdir_not_target),
    ({'monitored_dir'}, testdir_target, testdir_not_target)
])
def test_symbolic_change_target(tags_to_apply, main_folder, aux_folder, get_configuration, configure_environment,
                                restart_wazuh, wait_for_initial_scan):
    """ Check if syscheck updates the symlink target properly

    CHECK: Having a symbolic link pointing to a file/folder, change the target of the link to another file/folder.
    Ensure that the old file is being monitored and the new one is not before symlink_checker runs.
    Wait until symlink_checker runs and ensure that the new file is being monitored and the old one is not.

    :param main_folder: Directory that is being pointed at or contains the pointed file
    :param aux_folder: Directory that will be pointed at or will contain the future pointed file

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.
    """

    def modify_and_check_events(f1, f2, text):
        """ Modify the content of 2 given files. We assume the first one is being monitored and the other one is not.
            We expect a 'modified' event for the first one and a timeout for the second one.
        """
        modify_file_content(f1, file1, text)
        modify_file_content(f2, file1, text)
        check_time_travel(scheduled)
        modify = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        assert 'modified' in modify['data']['type'] and f1 in modify['data']['path'], \
            f"'modified' event not matching for {file1}"
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'

    # If symlink is pointing to a directory, we need to add files and expect their 'added' event (only if the file
    # is being created withing the pointed directory
    if main_folder == testdir_target:
        create_file(REGULAR, main_folder, file1, content='')
        create_file(REGULAR, aux_folder, file1, content='')
        check_time_travel(scheduled)
        add = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        assert 'added' in add['data']['type'] and file1 in add['data']['path'], \
            f"'added' event not matching for {file1}"
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
    else:
        create_file(REGULAR, aux_folder, file1, content='')
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)

    # Change the target of the symlink and expect events while there's no symcheck scan
    # Don't expect events from the new target
    if tags_to_apply == {'monitored_dir'}:
        modify_symlink(aux_folder, os.path.join(testdir_link, 'symlink2'))
    else:
        modify_symlink(aux_folder, os.path.join(testdir_link, 'symlink'), file=file1)
    modify_and_check_events(main_folder, aux_folder, 'Sample number one')

    wait_for_symlink_check(wazuh_log_monitor)
    wait_for_audit(whodata, wazuh_log_monitor)

    # Expect events the other way around now
    modify_and_check_events(aux_folder, main_folder, 'Sample number two')
