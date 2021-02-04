# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from test_fim.test_files.test_follow_symbolic_link.common import testdir_target, testdir1
from wazuh_testing import logger
from wazuh_testing.fim import (LOG_FILE_PATH,
                               generate_params, create_file, REGULAR, callback_detect_event,
                               modify_file, delete_file, check_time_travel)
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'FOLLOW_MODE': 'no'})
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

@pytest.mark.parametrize('tags_to_apply, path', [
    ({'monitored_file'}, testdir1),
    ({'monitored_dir'}, testdir_target)
])
def test_follow_symbolic_disabled(path, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                  wait_for_fim_start):
    """Check what happens when follow_symbolic_link option is set to "no".

    Ensure that the monitored symbolic link is considered a regular file and it will not follow its target path. It will
    only generate events if it changes somehow, not its target (file or directory)

    Parameters
    ----------
    path : str
        Path of the target file or directory
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    regular_file = 'regular1'
    error_msg = 'A "Sending FIM event: ..." event has been detected. No events should be detected at this time.'

    # If the symlink targets to a directory, create a file in it and ensure no event is raised.
    if tags_to_apply == {'monitored_dir'}:
        create_file(REGULAR, path, regular_file)
        check_time_travel(scheduled, monitor=wazuh_log_monitor)
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
            logger.error(error_msg)
            raise AttributeError(error_msg)

    # Modify the target file and don't expect any events
    modify_file(path, regular_file, new_content='Modify sample')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
        logger.error(error_msg)
        raise AttributeError(error_msg)

    # Delete the target file and don't expect any events
    delete_file(path, regular_file)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
        logger.error(error_msg)
        raise AttributeError(error_msg)
