# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sys
import subprocess
import gzip
import shutil

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, REGULAR, create_file, \
    generate_params, check_time_travel
from test_fim.test_report_changes.common import generate_string
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import check_apply_test, load_wazuh_configurations


# Marks

pytestmark = pytest.mark.tier(level=1)


# variables

test_directories = [os.path.join(PREFIX, 'testdir')]
nodiff_file = os.path.join(PREFIX, 'testdir_nodiff', 'regular_file')
directory_str = ','.join(test_directories)
testdir = test_directories[0]
unzip_diff_dir = os.path.join(PREFIX, 'unzip_diff')

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


# Functions


def extra_configuration_before_yield():
    """Create a folder to store diff files unzipped"""
    os.makedirs(unzip_diff_dir, exist_ok=True)


def extra_configuration_after_yield():
    """Delete the folder after the test"""
    shutil.rmtree(unzip_diff_dir, ignore_errors=True)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_report'}
])
@pytest.mark.parametrize('filename, folder, original_size, modified_size', [
    ('regular_0', testdir, 500, 500),
    ('regular_1', testdir, 30000, 30000),
    ('regular_2', testdir, 70000, 70000),
    ('regular_3', testdir, 10, 20000),
    ('regular_4', testdir, 10, 70000),
    ('regular_5', testdir, 20000, 10),
    ('regular_6', testdir, 70000, 10),
])
def test_large_changes(filename, folder, original_size, modified_size, tags_to_apply, get_configuration,
                       configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check content_changes shows the tag 'More changes' when it exceeds the maximum size.

    Every change in the content of the file shall produce an alert including
    the difference. But, if the difference is greater or equal than 59391 bytes, 'More changes'
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

    limit = 59391
    has_more_changes = False
    original_file = os.path.join(folder, filename)
    unzip_diff_file = os.path.join(unzip_diff_dir, filename + '-old')
    diff_file_path = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
    if sys.platform == 'win32':
        diff_file_path = os.path.join(diff_file_path, 'c')
        diff_file_path = os.path.join(diff_file_path, re.match(r'^[a-zA-Z]:(\\){1,2}(\w+)(\\){0,2}$', folder).group(2),
                                      filename, 'last-entry.gz')
    else:
        diff_file_path = os.path.join(diff_file_path, folder.strip('/'), filename, 'last-entry.gz')

    check_apply_test(tags_to_apply, get_configuration['tags'])
    fim_mode = get_configuration['metadata']['fim_mode']

    # Create the file and and capture the event.
    original_string = generate_string(original_size, '0')
    create_file(REGULAR, folder, filename, content=original_string)
    check_time_travel(fim_mode == 'scheduled', monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()

    # Store uncompressed diff file in backup folder
    with gzip.open(diff_file_path, 'rb') as f_in:
        with open(unzip_diff_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    # Modify the file with new content
    modified_string = generate_string(modified_size, '1')
    create_file(REGULAR, folder, filename, content=modified_string)
    check_time_travel(fim_mode == 'scheduled', monitor=wazuh_log_monitor)
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event).result()

    # Run the diff/fc command and get the output length
    try:
        if sys.platform == 'win32':
            subprocess.check_output(['fc', '/n', original_file, unzip_diff_file])
        else:
            subprocess.check_output(['diff', original_file, unzip_diff_file])
    except subprocess.CalledProcessError as e:
        # Inputs are different
        if e.returncode == 1:
            if sys.platform == 'win32' and b'*' not in e.output.split(b'\r\n')[1]:
                has_more_changes = True
            else:
                if len(e.output) > limit:
                    has_more_changes = True

    # Assert 'More changes' is shown when the command returns more than 'limit' characters
    if has_more_changes:
        assert 'More changes' in event['data']['content_changes'], '"More changes" not found within content_changes.'
    else:
        assert 'More changes' not in event['data']['content_changes'], '"More changes" found within content_changes.'

    # Assert old content is shown in content_changes
    assert '0' in event['data']['content_changes'], '"0" is the old value but it is not found within content_changes'

    # Assert new content is shown when old content is lower than the limit or platform is Windows
    if original_size < limit or sys.platform == 'win32':
        assert '1' in event['data']['content_changes'], '"1" is the new value but it is not found ' \
                                                        'within content_changes'
