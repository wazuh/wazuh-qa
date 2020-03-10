# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, callback_detect_event, \
    create_file, generate_params, modify_file_content, check_time_travel, delete_file, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# Variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories
timeout = global_parameters.default_timeout


# Extra functions
def extra_configuration_before_yield():
    # Create files before starting the service
    create_file(REGULAR, testdir1, 'regular0', content='')
    create_file(REGULAR, testdir1, 'regular1', content='')
    create_file(REGULAR, testdir1, 'regular2', content='')


# Configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('filename', [
    'regular0',
    'regular1',
    'regular2'
])
@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
def test_events_from_existing_files(filename, tags_to_apply, get_configuration,
                                    configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check if syscheck generates modified alerts for files that exists when starting the agent"""
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    mode = get_configuration['metadata']['fim_mode']

    # Modify file
    modify_file_content(testdir1, filename, new_content='Sample content')

    # Expect modified event
    check_time_travel(scheduled)
    modified_event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event,
                                             error_message='Did not receive expected '
                                                           '"Sending FIM event: ..." event').result()
    assert 'modified' in modified_event['data']['type'] and \
           os.path.join(testdir1, filename) in modified_event['data']['path']
    validate_event(modified_event, mode=mode)

    # Delete file
    delete_file(testdir1, filename)

    # Expect deleted event
    check_time_travel(scheduled)
    deleted_event = wazuh_log_monitor.start(timeout=timeout, callback=callback_detect_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()
    assert 'deleted' in deleted_event['data']['type'] and \
           os.path.join(testdir1, filename) in deleted_event['data']['path']
    validate_event(deleted_event, mode=mode)
