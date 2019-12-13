# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_configuration_error
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, PREFIX, control_service)


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'TEST_DIRECTORIES': directory_str}],
                                           metadata=[{'test_directories': directory_str}]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply', [
    ({'invalid_no_regex', 'invalid_scan'})
])
def test_invalid(tags_to_apply, get_configuration, configure_environment):
    """ Checks if an invalid configuration is detected

    Using invalid configurations with different attributes, expect an error message and syscheck unable to restart.

    * This test is intended to be used with invalid configurations files. Each execution of this test will fail to
     configure the environment properly.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    # Configuration error -> ValueError raised
    with pytest.raises(ValueError):
        control_service('restart')
    wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error)
