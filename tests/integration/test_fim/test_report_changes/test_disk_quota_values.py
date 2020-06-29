# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_disk_quota_limit_reached, generate_params
from test_fim.test_report_changes.common import disable_file_max_size, restore_file_max_size
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor


# Marks

pytestmark = [pytest.mark.tier(level=1)]


# Variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

if sys.platform == 'linux':
    test_dirs = ['/etc']
elif sys.platform == 'win32':
    test_dirs = [os.path.join("C:", os.sep, "Program Files (x86)")]
elif sys.platform == 'darwin':
    test_dirs = ['/Applications']
elif sys.platform == 'sunos5':
    test_dirs = ['/etc']
else:
    test_dirs = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_dirs)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_dirs[0]


# Configurations

disk_quota_values = ['1KB', '100KB', '1MB', '10MB']

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'no',
                                                           'FILE_SIZE_LIMIT': '10MB',
                                                           'DISK_QUOTA_ENABLED': 'yes',
                                                           'MODULE_NAME': __name__},
                                             apply_to_all=({'DISK_QUOTA_LIMIT': disk_quota_elem}
                                                           for disk_quota_elem in disk_quota_values))

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """
    Disable syscheck.file_max_size internal option
    """
    disable_file_max_size()


def extra_configuration_after_yield():
    """
    Restore syscheck.file_max_size internal option
    """
    restore_file_max_size()


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_diff'}
])
def test_disk_quota_values(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check that the disk_quota option for report_changes is working correctly.

    Monitor one of the system's folder and wait for the message alerting that the disk_quota limit has been reached.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout*25, callback=callback_disk_quota_limit_reached,
                            error_message='Did not receive expected '
                            '"The maximum configured size for the ... folder has been reached, ..." event.')
