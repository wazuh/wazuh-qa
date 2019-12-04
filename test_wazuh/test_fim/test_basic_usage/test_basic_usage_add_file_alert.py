# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing.fim import (CHECK_ALL, DEFAULT_TIMEOUT, FIFO, LOG_FILE_PATH, REGULAR, SOCKET,
                               callback_detect_event, create_file, validate_event, generate_params)
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories + [os.path.join(PREFIX, 'noexists')])

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories


# configurations

monitoring_modes = ['realtime', 'whodata']

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
conf_metadata = {'test_directories': directory_str, 'module_name': __name__}
p, m = generate_params(conf_params, conf_metadata, modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


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
@pytest.mark.parametrize('name, content, checkers, tags_to_apply', [
    ('file', 'Sample content', {CHECK_ALL}, {'ossec_conf'}),
    ('file2', b'Sample content', {CHECK_ALL}, {'ossec_conf'}),
    ('file3', '', {CHECK_ALL}, {'ossec_conf'}),
    ('file4', b'', {CHECK_ALL}, {'ossec_conf'}),
])
def test_add_file_alert(folder, name, content, checkers, tags_to_apply, get_configuration,
                                      configure_environment, restart_syscheckd, wait_for_initial_scan):
    """ Checks if an addition alert contains modification information

        Regular files must be monitored. Special files must not.

        :param folder: Name of the monitored folder
        :param name: Name of the file
        :param content: Content of the file
        :param checkers: Checks that will compared to the ones from the event

        * This test is intended to be used with valid configurations files. Each execution of this test will configure
          the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    regular_path = os.path.join(folder, name)

    # Create files
    create_file(REGULAR, folder, name, content=content)
    if os.path.exists(regular_path):
        os.remove(regular_path)
    create_file(REGULAR, folder, name, content='')

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event).result()

    try:
        assert 'added' in event['data']['type'] and os.path.join(folder, name) in event['data']['path']
    except AssertionError:
        if 'modified' in event['data']['type'] and os.path.join(folder, name) in event['data']['path']:
            raise AssertionError(f'Wrong event when adding a file')
