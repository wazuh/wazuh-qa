# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
from datetime import timedelta

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.time import TimeMachine
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
for direc in list(test_directories):
    test_directories.append(os.path.join(direc, 'subdir'))
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories[2:]
new_name = 'this_is_a_new_name'
old_name = 'old_name'

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def clean_directories(request):
    renamed_dir = os.path.join(PREFIX, getattr(request.module, 'new_name'))
    directories = getattr(request.module, 'test_directories')[0:2]
    directories.append(renamed_dir)
    for test_dir in directories:
        shutil.rmtree(test_dir, ignore_errors=True)
    yield
    shutil.rmtree(renamed_dir, ignore_errors=True)


# tests

@pytest.mark.parametrize('folder, tags_to_apply', [
    (testdir1, {'ossec_conf'}),
    (testdir2, {'ossec_conf'})
])
def test_rename(folder, tags_to_apply,
                get_configuration, clean_directories, configure_environment,
                restart_syscheckd, wait_for_initial_scan):
    """
    Check if syscheckd detects events when renaming directories or files.

    If we rename a directory or file, we expect 'deleted' and 'added' events.

    Parameters
    ----------
    folder : str
        Directory where the files will be created.
    """

    def expect_events(path):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event).result()
        try:
            assert 'added' in event['data']['type'] and path in event['data']['path'], \
                f'Deleted event not detected'
        except AssertionError:
            if 'deleted' not in event['data']['type'] and new_name not in event['data']['path']:
                raise AssertionError(f'Wrong event when renaming a non empty directory')

    check_apply_test(tags_to_apply, get_configuration['tags'])

    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    create_file(REGULAR, folder, old_name, content='')
    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='[ERROR] Did not receive expected "Sending FIM event: ..." event')

    # testdir1 will have renamed files within. testdir2 will be renamed with files within
    if folder == testdir1:
        # Change the file name
        os.rename(os.path.join(folder, old_name), os.path.join(folder, new_name))
        check_time_travel(scheduled)
        # Expect deleted and created events
        deleted = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=callback_detect_event,
                                          error_message='[ERROR] Did not receive expected '
                                                        '"Sending FIM event: ..." event'
                                          ).result()
        try:
            assert 'deleted' in deleted['data']['type'] and os.path.join(folder, old_name) in deleted['data']['path']
        except AssertionError:
            if 'added' not in deleted['data']['type'] and os.path.join(folder, old_name) not in deleted['data']['path']:
                raise AssertionError(f'Wrong event when renaming a file')

        added = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event,
                                        error_message='[ERROR] Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        try:
            assert 'added' in added['data']['type'] and os.path.join(folder, new_name) in added['data']['path']
        except AssertionError:
            if 'deleted' not in added['data']['type'] and os.path.join(folder, new_name) not in added['data']['path']:
                raise AssertionError(f'Wrong event when renaming a file')
    else:
        os.rename(folder, os.path.join(os.path.dirname(folder), new_name))
        check_time_travel(scheduled)
        expect_events(new_name)
        # Travel in time to force delete event in realtime/whodata
        if get_configuration['metadata']['fim_mode'] != 'scheduled':
            TimeMachine.travel_to_future(timedelta(hours=13))
        expect_events(folder)
