# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters

from test_fim.test_multiple_dirs.common import multiple_dirs_test, test_directories
from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'multiple_dirs.yaml')

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('dir_list, tags_to_apply', [
    (test_directories, {'multiple_dirs'})
])
def test_multiple_dirs(dir_list, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                       wait_for_initial_scan):
    """
    Check if syscheck can detect every event when adding, modifying and deleting a file within multiple monitored
    directories.

    These directories will be added in one single entry like so:
        <directories>testdir0, testdir1, ..., testdirn</directories>

    Parameters
    ----------
    dir_list : list
        List with all the directories to be monitored.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file = 'regular'
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    multiple_dirs_test(dir_list=dir_list, file=file, scheduled=scheduled, log_monitor=wazuh_log_monitor,
                       timeout=2 * global_parameters.default_timeout)
