# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, regular_file_cud, WAZUH_PATH, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir_reports'), os.path.join(PREFIX, 'testdir_nodiff')]
nodiff_file = os.path.join(PREFIX, 'testdir_nodiff', 'regular_file')

directory_str = ','.join(test_directories)
testdir_reports, testdir_nodiff = test_directories
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'NODIFF_FILE': nodiff_file,
                                                           'MODULE_NAME': __name__})

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_report'}
])
@pytest.mark.parametrize('folder, checkers', [
    (testdir_reports, options),
    (testdir_nodiff, options)
])
def test_reports_file_and_nodiff(folder, checkers, tags_to_apply,
                                 get_configuration, configure_environment,
                                 restart_syscheckd, wait_for_fim_start):
    """
    Check if report_changes events and diff truncated files are correct

    The report_changes attribute adds a new event property to the 'modified' sent event: 'content_changes'
    It has information about what changed from the previous content. To do so, it duplicates the file in the diff
    directory. We call this duplicated file 'diff_file'.

    Parameters
    ----------
    folder : str
        Directory where the files will be created.
    checkers : dict
        Syscheck checkers
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file_list = ['regular_file']
    is_truncated = folder == testdir_nodiff

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
                diff_file = os.path.join(diff_file, re.match(r'^[a-zA-Z]:(\\){1,2}(\w+)(\\){0,2}$', folder).group(2),
                                         file)
            else:
                diff_file = os.path.join(diff_file, folder.strip('/'), file)
            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, f'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if is_truncated:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                f'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                f'content_changes is truncated'

    regular_file_cud(folder, wazuh_log_monitor, file_list=file_list,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator])
