# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest


from test_fim.test_follow_symbolic_link.common import modify_symlink
from wazuh_testing.fim import (DEFAULT_TIMEOUT, LOG_FILE_PATH,
                               generate_params, create_file, REGULAR, SYMLINK, callback_detect_event,
                               modify_file, delete_file, check_time_travel)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, PREFIX)


# All tests in this module apply to linux only
pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin]


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir_link'), os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2')]
testdir_link, testdir1, testdir2 = test_directories

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


@pytest.fixture(scope='function')
def clean_directories(request):
    directories = getattr(request.module, 'test_directories')
    for folder in directories:
        for the_file in os.listdir(folder):
            file_path = os.path.join(folder, the_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)


# tests

@pytest.mark.parametrize('monitored_dir, non_monitored_dir1, non_monitored_dir2, sym_target, tags_to_apply', [
    (testdir_link, testdir1, testdir2, 'file', {'non_monitored_dir'}),
    (testdir_link, testdir1, testdir2, 'folder', {'non_monitored_dir'})
])
def test_symbolic_monitor_directory_with_symlink(monitored_dir, non_monitored_dir1, non_monitored_dir2,
                                                 sym_target, tags_to_apply, get_configuration, configure_environment,
                                                 clean_directories, restart_syscheckd, wait_for_initial_scan):
    """ Check what happens with a symlink and its target when syscheck monitors a directory with a symlink
    and not the symlink itself.

    When this happens, the symbolic link is considered a regular file and it will not follow its target path.
    It will only generate events if it changes somehow, not its target (file or directory)

    :param monitored_dir: Monitored directory
    :param non_monitored_dir1: Non-monitored directory
    :param non_monitored_dir2: Non-monitored directory

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    name1 = 'regular1'
    name2 = 'regular2'
    sl_name = 'symlink'
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
    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event)

    # Modify the target file and don't expect any event
    modify_file(non_monitored_dir1, name1, new_content='Modify sample')
    check_time_travel(scheduled)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)

    # Modify the target of the symlink and expect the modify event
    modify_symlink(target=b_path, path=sl_path)
    check_time_travel(scheduled)
    result = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()
    assert 'modified' in result['data']['type'], f"No 'modified' event when modifying symlink"

    # Remove and restore the target file. Don't expect any events
    delete_file(b_path, name2)
    create_file(REGULAR, non_monitored_dir1, name2, content='')
    check_time_travel(scheduled)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
