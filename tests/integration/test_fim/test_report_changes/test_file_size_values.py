# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, callback_file_size_limit_reached, generate_params, create_file, \
    check_time_travel, callback_detect_event, modify_file_content
from test_fim.test_report_changes.common import generateString, translate_size, disable_file_max_size, \
    restore_file_max_size, make_diff_file_path
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor


# Marks

pytestmark = [pytest.mark.tier(level=2)]


# Variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]


# Configurations

file_size_values = ['1KB', '100KB', '1MB', '10MB', '1GB']

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'yes',
                                                           'DISK_QUOTA_ENABLED': 'no',
                                                           'DISK_QUOTA_LIMIT': '2KB',
                                                           'MODULE_NAME': __name__},
                                             apply_to_all=({'FILE_SIZE_LIMIT': file_size_elem}
                                                           for file_size_elem in file_size_values))

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
@pytest.mark.parametrize('filename, folder', [
    ('regular_0', testdir1),
])
def test_file_size_values(tags_to_apply, filename, folder, get_configuration, configure_environment, restart_syscheckd,
                          wait_for_initial_scan):
    """
    Check that the file_size option for report_changes is working correctly.

    Create a file smaller than the limit and check that the compressed file has been created. If the first part is
    successful, increase the size of the file and expect the message for file_size limit reached and no compressed file
    in the queue/diff/local folder.

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
    is_big = get_configuration['metadata']['file_size_limit'] == '1GB'
    mult_big = 1 if not is_big else 3
    diff_file_path = make_diff_file_path(folder=folder, filename=filename)

    # Create file with a smaller size than the configured value
    to_write = generateString(int(size_limit / 2), '0')
    create_file(REGULAR, folder, filename, content=to_write)

    check_time_travel(scheduled)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout*mult_big, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event.').result()

    if not os.path.exists(diff_file_path):
        raise FileNotFoundError(f"{diff_file_path} not found. It should exist before increasing the size.")

    # Increase the size of the file over the configured value
    for _ in range(0, 3):
        modify_file_content(folder, filename, new_content=to_write)

    check_time_travel(scheduled)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout*mult_big,
                            callback=callback_file_size_limit_reached,
                            error_message='Did not receive expected '
                            '"File ... is too big for configured maximum size to perform diff operation" event.')

    if os.path.exists(diff_file_path):
        raise FileExistsError(f"{diff_file_path} found. It should not exist after incresing the size.")
