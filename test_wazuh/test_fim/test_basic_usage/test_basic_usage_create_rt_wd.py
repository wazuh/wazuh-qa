# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing.fim import (CHECK_ALL, FIFO, LOG_FILE_PATH, REGULAR, SOCKET,
                               callback_detect_event, create_file, validate_event)
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations


# variables

if sys.platform == 'win32':
    test_directories = [os.path.join('C:', os.sep, 'testdir1'), os.path.join('C:', os.sep, 'testdir2')]
    directory_str = "c:\\testdir1,c:\\testdir2,c:\\noexists"

else:
    test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
    directory_str = "/testdir1,/testdir2,/noexists"

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories


# configurations

monitoring_modes = ['realtime', 'whodata']
conf_params = []
conf_metadata = []
for mode in monitoring_modes:
    conf_params.append({'FIM_MODE': {mode: 'yes'}, 'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__})
    conf_metadata.append({'fim_mode': mode, 'test_directories': directory_str, 'module_name': __name__})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('name, filetype, content, checkers, tags_to_apply', [
    ('file', REGULAR, 'Sample content', {CHECK_ALL}, {'ossec_conf'}),
    ('file2', REGULAR, b'Sample content', {CHECK_ALL}, {'ossec_conf'}),
    ('socket_file', REGULAR if sys.platform == 'win32' else SOCKET, '', {CHECK_ALL}, {'ossec_conf'}),
    ('file3', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}),
    ('fifo_file', REGULAR if sys.platform == 'win32' else FIFO, '', {CHECK_ALL}, {'ossec_conf'}),
    ('file4', REGULAR, b'', {CHECK_ALL}, {'ossec_conf'}),
])
def test_create_file_realtime_whodata(folder, name, filetype, content, checkers, tags_to_apply, get_configuration,
                                      configure_environment, restart_syscheckd, wait_for_initial_scan):
    """ Checks if a special or regular file creation is detected by syscheck using realtime and whodata monitoring"""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create files
    create_file(filetype, folder, name, content=content)

    if filetype == REGULAR:
        # Wait until event is detected
        event = wazuh_log_monitor.start(timeout=5, callback=callback_detect_event).result()
        validate_event(event, checkers)
    else:
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)
