# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import time

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params, regular_file_cud
from wazuh_testing.tools import PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

directory_str = os.path.join(PREFIX, 'testdir1')
test_directories = [directory_str]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
def test_create_after_delete(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                             wait_for_initial_scan):
    """
    Check that a monitored directory keeps reporting events after deleting and creating it again. It tests
    that under Windows systems the directory watcher is refreshed after directory re-creation 1 second after.

    This test performs the following steps:
    - Monitor a directory that exist.
    - Create some files inside. Check that it does produce events in ossec.log.
    - Delete the directory and wait for a second.
    - Create the directory again and wait for a second.
    - Check that creating files within the directory do generate events again.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create the monitored directory with files and check that events are not raised
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file1', 'file2', 'file3'],
                     min_timeout=global_parameters.default_timeout, triggers_event=True)

    # Delete the directory
    os.rename(directory_str, f'{directory_str}_delete')
    shutil.rmtree(f'{directory_str}_delete', ignore_errors=True)
    time.sleep(5)

    # Re-create the directory
    os.makedirs(directory_str, exist_ok=True, mode=0o777)
    time.sleep(5)

    # Assert that events of new CUD actions are raised after next scheduled scan
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file4', 'file5', 'file6'],
                     min_timeout=global_parameters.default_timeout, triggers_event=True)
