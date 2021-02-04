# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_disk_quota_default, generate_params
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
DEFAULT_SIZE = 1 * 1024 * 1024


# Configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'MODULE_NAME': __name__})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_diff_default'}
])
def test_disk_quota_default(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check that the default value for disk_quota (1GB) is configured properly.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    disk_quota_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                               callback=callback_disk_quota_default,
                                               error_message='Did not receive expected '
                                               '"Maximum disk quota size limit configured to \'... KB\'." event'
                                               ).result()

    if disk_quota_value:
        assert disk_quota_value == str(DEFAULT_SIZE), 'Wrong value for disk_quota'
    else:
        raise AssertionError('Wrong value for disk_quota')
