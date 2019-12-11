# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import sys
from datetime import timedelta

import pytest

from wazuh_testing.fim import CHECK_ALL, LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, check_time_travel, validate_event, DEFAULT_TIMEOUT
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX, TimeMachine


# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories[:]
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

@pytest.mark.parametrize('folder, dest, file, filetype, tags_to_apply', [
    (testdir1, PREFIX, 'regular1', REGULAR, {'ossec_conf'}, ),
    (testdir2, os.path.join(testdir2,'subdir'), 'regular2', REGULAR, {'ossec_conf'}, ),
    (testdir2, os.path.join(PREFIX, 'etc'), 'regular3', REGULAR, {'ossec_conf'}, )
])
def test_move_file(folder, dest, file, filetype, tags_to_apply,
                      get_configuration, configure_environment,
                      restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd detects 'deleted' events of the files contained 
        in a folder that is being deleted.

        :param folder: Directory where the files will be created
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create files inside folder
    create_file(filetype, folder, file, content='')

    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event)

    # Move file
    shutil.move(os.path.join(folder,file), os.path.join(dest,file))
    check_time_travel(scheduled)

    # Expect deleted events
    event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event).result()
    if folder == testdir1:
        assert 'deleted' in event['data']['type'] and os.path.join(folder, file) in event['data']['path']
    else:
        assert 'added' in event['data']['type'] and os.path.join(dest, file) in event['data']['path']
        event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event).result()
        assert 'deleted' in event['data']['type'] and os.path.join(folder, file) in event['data']['path']
    