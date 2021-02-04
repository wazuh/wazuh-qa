# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_link, wait_for_symlink_check, wait_for_audit, testdir2
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
    extra_configuration_after_yield

from wazuh_testing import logger, global_parameters
from wazuh_testing.fim import (generate_params, create_file, REGULAR, callback_detect_event,
                               check_time_travel, LOG_FILE_PATH)
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# configurations

conf_params, conf_metadata = generate_params(extra_params={'FOLLOW_MODE': 'yes'},
                                             modes=['scheduled'])
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
    ({'nested_dir'}, testdir1, testdir2)
])
def test_symbolic_change_target_inside_folder(tags_to_apply, previous_target, new_target, get_configuration,
                                              configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if syscheck stops detecting events from previous target when pointing to a new folder

    CHECK: Having a symbolic link pointing to a folder which contains another monitored directory. Changing the target
    should not trigger 'added' events for the monitored subdirectory on the next scan.

    Parameters
    ----------
    previous_target : str
        Previous symlink target (path)
    new_target : str
        New symlink target (path).
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'new_file'
    symlink = 'symlink3'

    # Check create event
    create_file(REGULAR, previous_target, file1, content='')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event')

    # Change the target to another file and wait the symcheck to update the link information
    modify_symlink(new_target, os.path.join(testdir_link, symlink))
    wait_for_symlink_check(wazuh_log_monitor)
    wait_for_audit(whodata, wazuh_log_monitor)

    # Verify that no events are generated
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')
