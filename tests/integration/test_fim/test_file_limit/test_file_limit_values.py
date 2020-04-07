# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_value_file_limit, generate_params
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

file_limit_list = ['1', '10', '100', '1000', '10000']

p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1},
                       apply_to_all=({'FILE_LIMIT': file_limit_elem} for file_limit_elem in file_limit_list))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


@pytest.mark.parametrize('tags_to_apply', [
    {'file_limit_values'}
])
def test_file_limit_values(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check that a list of different values gets configured correctly in file_limit.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file_limit_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                               callback=callback_value_file_limit,
                                               error_message='Did not receive expected '
                                               '"DEBUG: ...: Maximum number of files to be monitored: ..." event'
                                               ).result()

    if file_limit_value:
        assert file_limit_value == get_configuration['metadata']['file_limit'], 'Wrong value for file_limit'
    else:
        raise AssertionError('Wrong value for file_limit')
