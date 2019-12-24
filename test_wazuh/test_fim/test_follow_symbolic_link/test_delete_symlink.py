# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from test_fim.test_follow_symbolic_link.common import configurations_path, testdir1, \
    testdir_link, wait_for_symlink_check, test_directories, \
    extra_configuration_after_yield, extra_configuration_before_yield, testdir_target, testdir_not_target, delete_f
from wazuh_testing.fim import (generate_params, create_file, REGULAR, SYMLINK, callback_detect_event,
                               check_time_travel, modify_file_content, LOG_FILE_PATH)
from wazuh_testing.tools import (check_apply_test,
                                 load_wazuh_configurations, FileMonitor)


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

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

@pytest.mark.parametrize('tags_to_apply, main_folder, aux_folder', [
    ({'monitored_file'}, testdir1, testdir_not_target),
    ({'monitored_dir'}, testdir_target, testdir_not_target)
])
def test_symbolic_delete_symlink(tags_to_apply, main_folder, aux_folder, get_configuration, configure_environment,
                                 restart_syscheckd, wait_for_initial_scan):
    """ Check if syscheck stops detecting events when deleting the monitored symlink.

    CHECK: Having a symbolic link pointing to a file/folder, remove that symbolic link file, wait for the symlink
    checker runs and modify the target file. No events should be detected. Restore the symbolic link and modify
    the target file again once symlink checker runs. Events should be detected now.

    :param main_folder: Directory that is being pointed at or contains the pointed file
    :param aux_folder: Directory that will be pointed at or will contain the future pointed file

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file1 = 'regular1'
    if tags_to_apply == {'monitored_dir'}:
        create_file(REGULAR, main_folder, file1, content='')
        check_time_travel(scheduled)
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)

    # Remove symlink and don't expect events
    symlink = 'symlink' if tags_to_apply == {'monitored_file'} else 'symlink2'
    delete_f(testdir_link, symlink)
    wait_for_symlink_check(wazuh_log_monitor)
    modify_file_content(main_folder, file1, new_content='Sample modification')
    check_time_travel(scheduled)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)

    # Restore symlink and modify the target again. Expect events now
    create_file(SYMLINK, testdir_link, symlink, target=os.path.join(main_folder, file1))
    wait_for_symlink_check(wazuh_log_monitor)
    modify_file_content(main_folder, file1, new_content='Sample modification 2')
    check_time_travel(scheduled)
    modify = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    assert 'modified' in modify['data']['type'] and file1 in modify['data']['path'], \
        f"'modified' event not matching for {file1}"
