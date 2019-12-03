# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.fim import CHECK_ALL, DEFAULT_TIMEOUT, LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories + [os.path.join(PREFIX, 'noexists')])
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories


# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
conf_metadata = {'test_directories': directory_str, 'module_name': __name__}
p, m = generate_params(conf_params, conf_metadata)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('checkers,  tags_to_apply', [
    ({CHECK_ALL}, {'ossec_conf'}),
])
def test_regular_file_changes(folder, checkers, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd detects regular file changes (add, modify, delete)

    :param folder: Directory where the files will be created
    :param checkers: Dict of syscheck checkers (check_all)

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
          the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file_list = ['regular0', 'regular1', 'regular2']
    min_timeout = 10

    regular_file_cud(folder, wazuh_log_monitor, file_list=file_list,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=min_timeout, options=checkers, triggers_event=True)
