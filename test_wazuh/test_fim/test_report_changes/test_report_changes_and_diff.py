# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

import pytest

from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, regular_file_cud, WAZUH_PATH)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations, set_configuration)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

if sys.platform == 'win32':
    test_directories = [os.path.join('C:', os.sep, 'testdir_reports'), os.path.join('C:', os.sep, 'testdir_nodiff')]
    directory_str = "c:\\testdir_reports,c:\\testdir_nodiff"
    nodiff_file = os.path.join('C:', os.sep, 'testdir_nodiff', 'regular_file')


else:
    test_directories = [os.path.join('/', 'testdir_reports'), os.path.join('/', 'testdir_nodiff')]
    directory_str = "/testdir_reports,/testdir_nodiff"
    nodiff_file = "testdir_nodiff/regular_file"
testdir_reports, testdir_nodiff = test_directories
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = set_configuration({'REPORT_CHANGES': {'report_changes': 'yes'},
                                                'TEST_DIRECTORIES': directory_str, 'NODIFF_FILE': nodiff_file,
                                                'MODULE_NAME': __name__},
                                               {'report_changes': 'yes',
                                                'test_directories': directory_str, 'nodiff_file': nodiff_file,
                                                'module_name': __name__})
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
                                 restart_syscheckd, wait_for_initial_scan):
    """ Check if report_changes events and diff truncated files are correct
    :param folder: Directory where the files will be created
    :param checkers: Dict of syscheck checkers (check_all)
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    min_timeout = 3
    file_list = ['regular_file']
    is_truncated = folder == testdir_nodiff

    def report_changes_validator(event):
        """ Validate content_changes attribute exists in the event """
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
                diff_file = os.path.join(diff_file, folder.strip('C:\\'), file)
            else:
                diff_file = os.path.join(diff_file, folder.strip('/'), file)
            assert (os.path.exists(diff_file)), f'{diff_file} does not exist'
            assert (event['data'].get('content_changes') is not None), f'content_changes is empty'

    def no_diff_validator(event):
        """ Validate content_changes value is truncated if the file is set to no_diff """
        if is_truncated:
            assert ('<Diff truncated because nodiff option>' in event['data'].get('content_changes')), \
                f'content_changes is not truncated'
        else:
            assert ('<Diff truncated because nodiff option>' not in event['data'].get('content_changes')), \
                f'content_changes is truncated'

    regular_file_cud(folder, wazuh_log_monitor, file_list=file_list,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=min_timeout, triggers_event=True,
                     validators_after_update=[report_changes_validator, no_diff_validator])
