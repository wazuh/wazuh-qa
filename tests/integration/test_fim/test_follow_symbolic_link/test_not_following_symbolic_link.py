# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from test_fim.test_follow_symbolic_link.common import modify_symlink

from wazuh_testing import global_parameters, logger
from wazuh_testing.fim import (LOG_FILE_PATH,
                               generate_params, create_file, REGULAR, SYMLINK, callback_detect_event,
                               modify_file, delete_file, check_time_travel)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir_link'), os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2')]
testdir_link, testdir1, testdir2 = test_directories

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

@pytest.mark.parametrize('monitored_dir, non_monitored_dir1, non_monitored_dir2, sym_target, tags_to_apply', [
    (testdir_link, testdir1, testdir2, 'file', {'non_monitored_dir'}),
    (testdir_link, testdir1, testdir2, 'folder', {'non_monitored_dir'})
])
def test_symbolic_monitor_directory_with_symlink(monitored_dir, non_monitored_dir1, non_monitored_dir2,
                                                 sym_target, tags_to_apply, get_configuration, configure_environment,
                                                 restart_syscheckd, wait_for_fim_start):
    """
    Check what happens with a symlink and its target when syscheck monitors a directory with a symlink
    and not the symlink itself.

    When this happens, the symbolic link is considered a regular file and it will not follow its target path.
    It will only generate events if it changes somehow, not its target (file or directory)

    Parameters
    ----------
    monitored_dir : str
        Monitored directory.
    non_monitored_dir1 : str
        Non-monitored directory.
    non_monitored_dir2 : str
        Non-monitored directory.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    name1 = f'{sym_target}regular1'
    name2 = f'{sym_target}regular2'
    sl_name = f'{sym_target}symlink'
    a_path = os.path.join(non_monitored_dir1, name1)
    b_path = os.path.join(non_monitored_dir1, name2) if sym_target == 'file' else non_monitored_dir2
    sl_path = os.path.join(monitored_dir, sl_name)
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create regular files out of the monitored directory and don't expect its event
    create_file(REGULAR, non_monitored_dir1, name1, content='')
    create_file(REGULAR, non_monitored_dir1, name2, content='')
    target = a_path if sym_target == 'file' else non_monitored_dir1
    create_file(SYMLINK, monitored_dir, sl_name, target=target)

    # Create the syslink and expect its event, since it's withing the monitored directory
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event')

    # Modify the target file and don't expect any event
    modify_file(non_monitored_dir1, name1, new_content='Modify sample')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Modify the target of the symlink and expect the modify event
    modify_symlink(target=b_path, path=sl_path)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    result = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()
    if 'modified' in result['data']['type']:
        logger.info("Received modified event. No more events will be expected.")
    elif 'deleted' in result['data']['type']:
        logger.info("Received deleted event. Now an added event will be expected.")
        result = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event').result()
        assert 'added' in result['data']['type'], f"The event {result} should be of type 'added'"
    else:
        assert False, f"Detected event {result} should be of type 'modified' or 'deleted'"

    # Remove and restore the target file. Don't expect any events
    delete_file(b_path, name2)
    create_file(REGULAR, non_monitored_dir1, name2, content='')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')
