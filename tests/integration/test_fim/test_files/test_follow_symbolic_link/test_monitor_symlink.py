# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import wazuh_testing.fim as fim

from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    testdir_target, delete_f
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
    extra_configuration_after_yield
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

@pytest.mark.parametrize('tags_to_apply, main_folder', [
    ({'monitored_file'}, testdir1),
    ({'monitored_dir'}, testdir_target)
])
def test_symbolic_monitor_symlink(tags_to_apply, main_folder, get_configuration, configure_environment,
                                  restart_syscheckd, wait_for_fim_start):
    """Check what happens with a symlink and its target when syscheck monitors it.

    CHECK: Having a symbolic link pointing to a file/folder, modify and delete the file. Check that alerts are
    being raised.

    Args:
        main_folder (str): Directory that is being pointed at or contains the pointed file.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If a expected event wasn't triggered.
        ValueError: If the event's type and path are not the expected.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file1 = 'regular1'

    # Add creation if symlink is pointing to a folder
    if tags_to_apply == {'monitored_dir'}:
        fim.create_file(fim.REGULAR, main_folder, file1, content='')
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        add = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event).result()
        assert 'added' in add['data']['type'] and file1 in add['data']['path'], \
            "'added' event not matching"

    # Modify the linked file and expect an event
    fim.modify_file_content(main_folder, file1, 'Sample modification')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    modify = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()
    assert 'modified' in modify['data']['type'] and file1 in modify['data']['path'], \
        "'modified' event not matching"

    # Delete the linked file and expect an event
    delete_f(main_folder, file1)
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    delete = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()
    assert 'deleted' in delete['data']['type'] and file1 in delete['data']['path'], \
        "'deleted' event not matching"
