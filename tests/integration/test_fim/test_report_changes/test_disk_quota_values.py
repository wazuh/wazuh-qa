# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import re

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, callback_disk_quota_limit_reached, generate_params, create_file, \
    check_time_travel, callback_detect_event, WAZUH_PATH, modify_file_content
from test_fim.test_report_changes.common import generateString, translate_size
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

disk_quota_values = ['1KB', '100KB', '1MB', '10MB']

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'no',
                                                           'FILE_SIZE_LIMIT': '1KB',
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

def new_mult(configured_size=1):
    """
    Returns the number needed to multiply the string to write in the file.

    Parameters
    ----------
    configured_size : int, optional
        Configured size in KB. Default `1`

    Returns
    -------
    mult : int
        Number to multiply the string to write.
    """
    mult = 1

    if configured_size == 1:
        mult = 2
    elif configured_size == 100:
        mult = 31
    elif configured_size == 1024:
        mult = 308
    elif configured_size == 10 * 1024:
        mult = 3101

    return mult


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_diff'}
])
@pytest.mark.parametrize('filename, folder', [
    ('regular_0', testdir1),
])
def test_disk_quota_values(tags_to_apply, filename, folder, get_configuration, configure_environment, restart_syscheckd,
                           wait_for_initial_scan):
    """
    Check that the disk_quota option for report_changes is working correctly.

    Create a file which compressed version is smaller than the limit and check that the compressed file has been
    created. If the first part is successful, increase the size of the file and expect the message for disk_quota limit
    reached and no compressed file in the queue/diff/local folder.

    Parameters
    ----------
    filename : str
        Name of the file to be created.
    folder : str
        Directory where the files are being created.
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    size_limit = translate_size(get_configuration['metadata']['file_size_limit'])
    diff_file_path = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
    original_len = 1000000

    if sys.platform == 'win32':
        diff_file_path = os.path.join(diff_file_path, 'c')
        diff_file_path = os.path.join(diff_file_path, re.match(r'^[a-zA-Z]:(\\){1,2}(\w+)(\\){0,2}$', folder).group(2),
                                      filename, 'last-entry.gz')
    else:
        diff_file_path = os.path.join(diff_file_path, folder.strip('/'), filename, 'last-entry.gz')

    # Create file with a compressed version smaller than the disk_quota limit
    to_write = generateString(original_len, '0')
    create_file(REGULAR, folder, filename, content=to_write)

    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event.').result()

    if not os.path.exists(diff_file_path):
        pytest.raises(FileNotFoundError(f"{diff_file_path} not found. It should exist before increasing the size."))

    # Modify file to increase the size and make its compressed version bigger than the disk_quota limit
    modify_file_content(folder, filename, new_content=to_write*new_mult(size_limit))

    check_time_travel(scheduled)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_disk_quota_limit_reached,
                            error_message='Did not receive expected '
                            '"File ... is too big for configured maximum size to perform diff operation" event.')

    if os.path.exists(diff_file_path):
        pytest.raises(FileExistsError(f"{diff_file_path} found. It should not exist after incresing the size."))
