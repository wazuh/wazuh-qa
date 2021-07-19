# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import tempfile

import pytest
from test_fim.test_files.test_report_changes.common import translate_size
from wazuh_testing.fim import LOG_FILE_PATH, callback_disk_quota_limit_reached, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import remove_file, random_string, write_file
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = [pytest.mark.tier(level=1)]

# Variables
extended_timeout = 30
compression_ratio = 12
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
temp_dir = tempfile.gettempdir()

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_disk_quota_values.yaml')


# Configurations
disk_quota_values = ['1KB', '100KB', '1MB', '10MB']

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': temp_dir,
                                                           'FILE_SIZE_ENABLED': 'no',
                                                           'DISK_QUOTA_ENABLED': 'yes',
                                                           'MODULE_NAME': __name__},
                                             apply_to_all=({'DISK_QUOTA_LIMIT': disk_quota_elem}
                                                           for disk_quota_elem in disk_quota_values))

configuration_ids = [f"disk_quota_limit_{x['disk_quota_limit']}" for x in conf_metadata]

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def create_specific_size_file(get_configuration, request):
    """Create a file with a specific size requested from test configuration"""
    size = get_configuration['metadata']['disk_quota_limit']
    # Translate given size from string to number in bytes
    translated_size = translate_size(configured_size=size)
    write_file(os.path.join(temp_dir, 'test'), random_string(translated_size*compression_ratio))

    yield

    remove_file(os.path.join(temp_dir, 'test'))


# Tests
def test_disk_quota_values(get_configuration, configure_environment, create_specific_size_file, restart_syscheckd):
    """Check that the disk_quota option for report_changes is working correctly.

    Monitor one of the system's folder and wait for the message alerting that the disk_quota limit has been reached.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    wazuh_log_monitor.start(timeout=extended_timeout, callback=callback_disk_quota_limit_reached,
                            error_message='Did not receive expected '
                                          '"The maximum configured size for the ... folder has been reached, ..." event.')
