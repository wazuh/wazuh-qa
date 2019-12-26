# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing.fim import DEFAULT_TIMEOUT, LOG_FILE_PATH, regular_file_cud, WAZUH_PATH, generate_params
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX

# Marks

pytestmark = pytest.mark.tier(level=2)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path,
                                   'wazuh_conf_win32.yaml' if sys.platform == 'win32' else 'wazuh_conf.yaml')

test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir1', 'subdir'),
                    os.path.join(PREFIX, 'testdir1', 'ignore_this'),
                    os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_nodiff, testdir2, testdir2_sub = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params()

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('folder, filename, content, hidden_content, tags_to_apply', [
    (testdir1, 'testfile', "Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'btestfile', b"Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, 'testfile2', "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1, "btestfile2.nodiff", b"", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir1, "btestfile2.nodiffd", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile', "Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'btestfile', b"Sample content", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, 'testfile2', "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, "btestfile2", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir1_sub, ".nodiff.btestfile", b"", False, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.nodiff", b"other content", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2, "another.nodiffd", b"other content", False, {'valid_regex'}),
    (testdir2_sub, "another.nodiff", b"other content", True, {'valid_regex1', 'valid_regex2', 'valid_regex3'}),
    (testdir2_sub, "another.nodiffd", b"other content", False, {'valid_regex'}),
    (testdir2, "another.nodiffd2", "", False, {'valid_regex', 'valid_no_regex'}),
    (testdir2, "another.nodiff2", "", True, {'valid_regex2', 'valid_regex3'}),
    (testdir1, 'nodiff_prefix_test.txt', "test", False,
     {'valid_regex1', 'valid_regex2', 'valid_regex3', 'valid_regex4'}),
    (testdir1, 'nodiff_prefix_test.txt', "test", True, {'valid_regex5'}),
    (testdir1, 'whatever.txt', "test", True, {'valid_empty'}),
    (testdir2, 'whatever2.txt', "test", True, {'valid_empty'})
])
def test_no_diff_subdirectory(folder, filename, content, hidden_content,
                              tags_to_apply, get_configuration,
                              configure_environment, restart_syscheckd,
                              wait_for_initial_scan):
    """ Checks files are ignored in the subdirectory according to configuration

    When using the nodiff option for a file in syscheck configuration, every time we get an event from this file,
    we won't be able to see its content. We'll see 'Diff truncated because nodiff option' instead.

    :param folder: Directory where the file is being created
    :param filename: Name of the file to be created
    :param content: Content to fill the new file
    :param hidden_content: True if content must be truncated,, False otherwise
    :param tags_to_apply: Run test if matches with a configuration identifier, skip otherwise

    * This test is intended to be used with valid nodiff configurations. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    files = {filename: content}

    def report_changes_validator(event):
        """ Validate content_changes attribute exists in the event """
        for file in files:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')

            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')

            diff_file = os.path.join(diff_file, folder.strip(PREFIX), file)

            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, f'content_changes is empty'

    def no_diff_validator(event):
        """ Validate content_changes value is truncated if the file is set to no_diff """
        if hidden_content:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                f'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                f'content_changes is truncated'

    regular_file_cud(folder, wazuh_log_monitor, file_list=files,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=DEFAULT_TIMEOUT, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator])
