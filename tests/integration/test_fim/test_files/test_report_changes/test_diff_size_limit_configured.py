# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_diff_size_limit_value, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]
DIFF_LIMIT_VALUE = 2

# Configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'DIFF_SIZE_LIMIT': {'diff_size_limit': '2kb'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'yes',
                                                           'FILE_SIZE_LIMIT': '1GB',
                                                           'DISK_QUOTA_ENABLED': 'no',
                                                           'DISK_QUOTA_LIMIT': '2KB',
                                                           'MODULE_NAME': __name__})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_diff_size_limit'}
])
def test_diff_size_limit_default(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check that the diff_size_limit option is configured properly when the global file_size variable is different.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    diff_size_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                              callback=callback_diff_size_limit_value,
                                              error_message='Did not receive expected '
                                                            '"Maximum file size limit configured to \'... KB\'..." event'
                                              ).result()

    if diff_size_value:
        assert diff_size_value == str(DIFF_LIMIT_VALUE), 'Wrong value for diff_size_limit'
    else:
        raise AssertionError('Wrong value for diff_size_limit')
