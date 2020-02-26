# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
from test_fim.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_link, wait_for_symlink_check, wait_for_audit
# noinspection PyUnresolvedReferences
from test_fim.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
    extra_configuration_after_yield

from wazuh_testing import logger
from wazuh_testing.fim import (generate_params, callback_detect_event,
                               check_time_travel, modify_file_content, LOG_FILE_PATH)
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'FOLLOW_MODE': 'yes'})
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

@pytest.mark.parametrize('tags_to_apply', [
    {'monitored_file'}
])
def test_symbolic_revert_symlink(tags_to_apply, get_configuration, configure_environment,
                                 restart_syscheckd, wait_for_initial_scan):
    """
    Check if syscheck detects new targets properly

    CHECK: Having a symbolic link pointing to a file/folder, change its target to a folder. Check that the old file
    is not being monitored anymore and the new folder is. Revert the target change and ensure the file is
    being monitored and the folder is not.
    """

    def modify_and_assert(file):
        modify_file_content(testdir1, file, new_content='Sample modification')
        check_time_travel(scheduled)
        ev = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        assert 'modified' in ev['data']['type'] and os.path.join(testdir1, file) in ev['data']['path'], \
            f"'modified' event not matching for {testdir1} {file}"

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'
    file2 = 'regular2'

    # Don't expect an event since it is not being monitored yet
    modify_file_content(testdir1, file2, new_content='Sample modification')
    check_time_travel(scheduled)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Change the target to the folder and now expect an event
    modify_symlink(testdir1, os.path.join(testdir_link, 'symlink'))
    wait_for_symlink_check(wazuh_log_monitor)
    wait_for_audit(whodata, wazuh_log_monitor)
    modify_and_assert(file2)

    # Modify symlink target, wait for sym_check to update it
    modify_symlink(os.path.join(testdir1, file1), os.path.join(testdir_link, 'symlink'))
    wait_for_symlink_check(wazuh_log_monitor)
    modify_file_content(testdir1, file2, new_content='Sample modification2')
    check_time_travel(scheduled)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')
    modify_and_assert(file1)
