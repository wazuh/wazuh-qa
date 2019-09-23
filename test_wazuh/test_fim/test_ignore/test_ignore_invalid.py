# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_configuration_error
from wazuh_testing.tools import FileMonitor, load_yaml


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
section_configuration_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = [configuration for configuration in
                  load_yaml(section_configuration_path)
                  if 'invalid_no_regex' in configuration['checks']]


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('checks', [
    ({'invalid_no_regex'})
])
def test_ignore(checks, get_configuration, configure_environment, restart_wazuh):
    """Checks if an invalid ignore configuration is detected."""
    if not (checks.intersection(get_configuration['checks']) or
       'all' in checks):
        pytest.skip("Does not apply to this config file")

    wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error)
