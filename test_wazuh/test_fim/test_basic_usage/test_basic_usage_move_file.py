# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import sys
from datetime import timedelta

import pytest

from wazuh_testing.fim import CHECK_ALL, LOG_FILE_PATH, generate_params, create_file,REGULAR, \
    callback_detect_event, check_time_travel, validate_event, DEFAULT_TIMEOUT, delete_file
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX, TimeMachine


# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories
timeout = DEFAULT_TIMEOUT


# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
conf_metadata = {'test_directories': directory_str, 'module_name': __name__}
p, m = generate_params(conf_params, conf_metadata)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder, file, file_content, filetype, tags_to_apply', [
    (testdir1, 'regular1', '' ,REGULAR, {'ossec_conf'}, )
])
def test_move_file_1(folder, file, file_content, filetype, tags_to_apply,
                      get_configuration, configure_environment,
                      restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd does not detect 'added' event from a file that was 
        moved to a directory not monitored.

        :param folder: Directory where the files will be created
        :param file: File name
        :filetype: File type
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
 
    # Create file inside folder
    create_file(filetype, folder, file, content=file_content)

    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event)

    # Move file to directory not monitored
    dest = PREFIX
    delete_file(folder, file)
    create_file(filetype, dest, file, content=file_content)
    check_time_travel(scheduled)

    # Expect deleted events
    event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event).result()
    assert 'deleted' in event['data']['type'] and os.path.join(folder, file) in event['data']['path']

    # Remove file
    delete_file(dest, file)

@pytest.mark.parametrize('folder, file, file_content, filetype, tags_to_apply', [
    (testdir1, 'regular2', '', REGULAR, {'ossec_conf'}, )
])
def test_move_file_2(folder, file, file_content, filetype, tags_to_apply,
                      get_configuration, configure_environment,
                      restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd detects 'added' and 'deleted' events from a file that was 
        moved to subdirectory.

        :param folder: Directory where the files will be created
        :param file: File name
        :filetype: File type
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
 
    # Create file inside folder
    create_file(filetype, folder, file, content=file_content)

    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event)

    # Move file to monitored subdirectory
    dest = os.path.join(folder, "subdir")
    delete_file(folder, file)
    create_file(filetype, dest, file, content=file_content)
    check_time_travel(scheduled)

    # Expect added and deleted events
    deleted = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event).result()
    try:
        assert 'deleted' in deleted['data']['type'] and os.path.join(folder, file) in deleted['data']['path']
    except AssertionError:
        if 'added' not in deleted['data']['type'] and os.path.join(dest, file) not in deleted['data']['path']:
            raise AssertionError(f'Wrong event when moving a file')

    added = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event).result()
    try:
        assert 'added' in added['data']['type'] and os.path.join(dest, file) in added['data']['path']
    except AssertionError:
        if 'deleted' not in added['data']['type'] and os.path.join(folder, file) not in added['data']['path']:
            raise AssertionError(f'Wrong event when moving a file')



@pytest.mark.parametrize('folder, file, file_content, filetype, tags_to_apply', [
    (testdir1, 'regular3', '', REGULAR, {'ossec_conf'}, )
])
def test_move_file_3(folder, file, file_content, filetype, tags_to_apply,
                      get_configuration, configure_environment,
                      restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd detects 'added' and 'deleted' events from a file that was 
        moved to another monitored directory.

        :param folder: Directory where the files will be created
        :param file: File name
        :filetype: File type
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
 
    # Create file inside folder
    create_file(filetype, folder, file, content=file_content)

    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event)

    # Move file to monitored directory
    dest = testdir2
    delete_file(folder, file)
    create_file(filetype, dest, file, content=file_content)
    check_time_travel(scheduled)

    # Expect added and deleted events
    deleted = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event).result()
    try:
        assert 'deleted' in deleted['data']['type'] and os.path.join(folder, file) in deleted['data']['path']
    except AssertionError:
        if 'added' not in deleted['data']['type'] and os.path.join(dest, file) not in deleted['data']['path']:
            raise AssertionError(f'Wrong event when moving a file')

    added = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event).result()
    try:
        assert 'added' in added['data']['type'] and os.path.join(dest, file) in added['data']['path']
    except AssertionError:
        if 'deleted' not in added['data']['type'] and os.path.join(folder, file) not in added['data']['path']:
            raise AssertionError(f'Wrong event when moving a file')
