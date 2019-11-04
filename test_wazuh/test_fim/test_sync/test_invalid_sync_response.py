# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import datetime, timedelta
import pytest
import time
from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_synchronization, detect_initial_scan, callback_configuration_warning)
from wazuh_testing.tools import (FileMonitor, truncate_file, check_apply_test, load_wazuh_configurations, reformat_time, TimeMachine)


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
    """Checks if an invalid ignore configuration is detected."""
    check_apply_test({'sync_invalid'}, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=3, callback=callback_configuration_warning)
