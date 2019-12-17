# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from test_fim.test_follow_symbolic_link.common import configurations_path, testdir1, \
    test_directories, extra_configuration_after_yield, extra_configuration_before_yield, testdir_target, delete_f
from wazuh_testing.fim import (generate_params, create_file, REGULAR, callback_detect_event,
                               check_time_travel, modify_file_content, LOG_FILE_PATH)
from wazuh_testing.tools import (check_apply_test,
                                 load_wazuh_configurations, FileMonitor)

# All tests in this module apply to linux and macos only
pytestmark = [pytest.mark.linux, pytest.mark.darwin]

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

@pytest.mark.parametrize('tags_to_apply, main_folder', [
    ({'monitored_file'}, testdir1),
    ({'monitored_dir'}, testdir_target)
])
def test_symbolic_monitor_symlink(tags_to_apply, main_folder, get_configuration, configure_environment,
                                  restart_syscheckd, wait_for_initial_scan):
    """ Check what happens with a symlink and its target when syscheck monitors it.

    CHECK: Having a symbolic link pointing to a file/folder, modify and delete the file. Check that alerts are
    being raised.

    :param main_folder: Directory that is being pointed at or contains the pointed file

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file1 = 'regular1'

    # Add creation if symlink is pointing to a folder
    if tags_to_apply == {'monitored_dir'}:
        create_file(REGULAR, main_folder, file1, content='')
        check_time_travel(scheduled)
        add = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        assert 'added' in add['data']['type'] and file1 in add['data']['path'], \
            f"'added' event not matching"

    # Modify the linked file and expect an event
    modify_file_content(main_folder, file1, 'Sample modification')
    check_time_travel(scheduled)
    modify = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    assert 'modified' in modify['data']['type'] and file1 in modify['data']['path'], \
        f"'modified' event not matching"

    # Delete the linked file and expect an event
    delete_f(main_folder, file1)
    check_time_travel(scheduled)
    delete = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
    assert 'deleted' in delete['data']['type'] and file1 in delete['data']['path'], \
        f"'deleted' event not matching"
