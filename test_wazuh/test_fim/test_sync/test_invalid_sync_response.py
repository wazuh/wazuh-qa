# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_configuration_warning
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations


# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_invalid_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def test_invalid_sync_response(get_configuration, configure_environment, restart_syscheckd):
    """Checks if an invalid ignore configuration is detected by catching the warning message displayed on the log.

    This test is intended to be used with valid configurations files. Each execution of this test will configure the
    environment properly and restart the service. No wait for the initial scan in this case as we need to detect the
    warning message.
    """
    check_apply_test({'sync_invalid'}, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=3, callback=callback_configuration_warning)
