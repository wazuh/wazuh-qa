# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, REGULAR, create_file, delete_file, \
    generate_params, check_time_travel
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import check_apply_test, load_wazuh_configurations


# Marks

pytestmark = pytest.mark.tier(level=1)


# variables

test_directories = [os.path.join(PREFIX, 'testdir')]
nodiff_file = os.path.join(PREFIX, 'testdir_nodiff', 'regular_file')
directory_str = ','.join(test_directories)
testdir = test_directories[0]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')


# configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'NODIFF_FILE': nodiff_file,
                                                           'MODULE_NAME': __name__})
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_report'}
])
@pytest.mark.parametrize('filename, folder, original_size, modified_size', [
    ('regular_0', testdir, 29660, 29660),
    ('regular_1', testdir, 30000, 30000),
    ('regular_2', testdir, 70000, 70000),
    ('regular_4', testdir, 10, 29660),
    ('regular_5', testdir, 10, 70000),
    ('regular_6', testdir, 29660, 10),
    ('regular_6', testdir, 70000, 10),
])
def test_report_changes_big(filename, folder, original_size, modified_size, tags_to_apply, get_configuration,
                            configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check content_changes when it exceeds the maximum size.

    Every change in the content of the file shall produce an alert including
    the difference. But, if the difference is greater or equal than 59370 bytes, 'More changes'
    appears instead.

    Parameters
    ----------
    filename : str
        Name of the file to be created.
    folder : str
        Directory where the files are being created.
    original_size : int
        Size of each file in bytes before being modified.
    modified_size : int
        Size of each file in bytes after being modified.
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    fim_mode = get_configuration['metadata']['fim_mode']
    limit = 59370

    # Create the file and and capture the event.
    create_file(REGULAR, folder, filename, content=b'0'*original_size)
    check_time_travel(fim_mode == 'scheduled')
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()

    # Modify the file with new content
    create_file(REGULAR, folder, filename, content=b'1'*modified_size)
    check_time_travel(fim_mode == 'scheduled')
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()

    # Assert old content is shown in content_changes when it is lower than the limit.
    if original_size < limit:
        assert '0' * original_size in event['data']['content_changes']
    # Assert new content is shown when it is lower than the limit (and the sum of both is still lower)
    if modified_size < limit and (original_size + modified_size) < limit:
        assert '1' * modified_size in event['data']['content_changes'], 'Not equal'
    # Assert 'More changes' is shown when the sum of old and new content is greater than the limit.
    if (original_size + modified_size) >= limit:
        assert 'More changes' in event['data']['content_changes']

    # Delete all created files
    delete_file(folder, filename)
    check_time_travel(fim_mode == 'scheduled')
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()
