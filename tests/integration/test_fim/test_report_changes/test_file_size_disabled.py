# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, callback_file_size_limit_reached, generate_params, create_file, \
    check_time_travel
from test_fim.test_report_changes.common import generateString
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


# Configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'no',
                                                           'FILE_SIZE_LIMIT': '1KB',
                                                           'DISK_QUOTA_ENABLED': 'yes',
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
    {'ossec_conf_diff'}
])
@pytest.mark.parametrize('filename, folder, size', [
    ('regular_0', testdir1, 1000000),
])
def test_file_size_disabled(tags_to_apply, filename, folder, size, get_configuration, configure_environment,
                            restart_syscheckd, wait_for_initial_scan):
    """
    Check that the file_size option is disabled correctly.

    Creates a file larger than the configured file_size limit and checks that the message about reaching the limit does
    not appear in the log.

    Parameters
    ----------
    filename : str
        Name of the file to be created.
    folder : str
        Directory where the files are being created.
    size : int
        Size of each file in bytes.
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    to_write = generateString(size, '0')
    create_file(REGULAR, folder, filename, content=to_write)

    check_time_travel(scheduled)

    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_file_size_limit_reached)
