# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from time import sleep

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, callback_file_limit_capacity, delete_file, \
    generate_params, create_file, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
base_file_name = "test_file"
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_delete_full.yaml')
testdir1 = test_directories[0]
NUM_FILES = 7
NUM_FILES_TO_CREATE = 8

# Configurations

file_limit_list = ['10']
conf_params = {'TEST_DIRECTORIES': testdir1,
               'LIMIT': str(NUM_FILES)
               }

p, m = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions


def extra_configuration_before_yield():
    """Generate files to fill database"""

    create_file(REGULAR, testdir1, f'{base_file_name}{10}')
    for i in range(2, NUM_FILES_TO_CREATE):
        create_file(REGULAR, testdir1, f'{base_file_name}{i}', content='content')


# Tests


@pytest.mark.parametrize('folder, file_name, tags_to_apply', [
    (testdir1, f'{base_file_name}{1}', {'tags_delete_full'})
])
def test_file_limit_delete_full(folder, file_name, tags_to_apply,
                                get_configuration, configure_environment, restart_syscheckd):
    """
    This test checks a specific case:
    If in a file (for example test_1) is not inserted in the database and a file ended in 0 (for example test_10) is
    inserted in the DB, after deleting test_1, the delete alert was raised for test_10.

    Parameters
    ----------
    folder: path
        Path to the folder where the test is going to be executed.
    file_name:
        base name of the file (in the example above it will be test_)
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    database_state = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                             callback=callback_file_limit_capacity,
                                             error_message='Did not receive expected '
                                                           '"DEBUG: ...: Sending DB 100% full alert." event').result()

    if database_state:
        assert database_state == '100', 'Wrong value for full database alert'

    create_file(REGULAR, testdir1, file_name)
    sleep(2)

    delete_file(folder, file_name)

    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event).result()
        assert event is None, 'No events should be detected.'

    delete_file(folder, f'{file_name}{0}')

    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event,
                                    error_message='Did not receive expected deleted event').result()

    assert event['data']['path'] == os.path.join(folder, f'{file_name}{0}')
