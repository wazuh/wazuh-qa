# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, generate_params, regular_file_cud, DEFAULT_TIMEOUT,
                               callback_detect_end_scan)
from wazuh_testing.tools import FileMonitor, load_wazuh_configurations, PREFIX

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_directories = [os.path.join(PREFIX, 'testdir'), os.path.join(PREFIX, 'not_exists')]

directory_str = test_directories[0]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_disabled.yaml')
testdir, testdir_not_exists = test_directories

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder', [testdir, testdir_not_exists])
def test_disabled(folder, get_configuration, configure_environment, restart_syscheckd):
    """Check if syscheckd sends events when disabled="yes".

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
      the environment properly, restart the service and wait for the initial scan.

    Parameters
    ----------
    folder : str
        Path where files will be created.
    """
    # Expect a timeout when checking for syscheckd initial scan
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=20, callback=callback_detect_end_scan)

    # Use `regular_file_cud` and don't expect any event
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    regular_file_cud(folder, wazuh_log_monitor, time_travel=scheduled, min_timeout=DEFAULT_TIMEOUT,
                     triggers_event=False)
