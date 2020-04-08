# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_file_limit_capacity, generate_params, create_file, REGULAR, \
                                regular_file_cud, callback_file_limit_full_database
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# Configurations

p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1})

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Functions


def extra_configuration_before_yield():
    """Generate files to fill database"""
    for i in range(0, 10):
        create_file(REGULAR, testdir1, 'file_' + str(i), content='content')

# Tests


@pytest.mark.parametrize('tags_to_apply', [
    {'file_limit_full'}
])
def test_file_limit_full(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check that the full database alerts are being sent.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    database_state = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                             callback=callback_file_limit_capacity,
                                             error_message='Did not receive expected '
                                             '"DEBUG: ...: Sending DB 100%% full alert." event').result()

    if database_state:
        assert database_state == '100', 'Wrong value for full database alert'

    if get_configuration['metadata']['fim_mode'] != 'scheduled':
        create_file(REGULAR, testdir1, 'file_full', content='content')

        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_file_limit_full_database,
                                error_message='Did not receive expected '
                                '"DEBUG: ...: Couldn\'t insert \'...\' entry into DB. The DB is full, ..." event')
