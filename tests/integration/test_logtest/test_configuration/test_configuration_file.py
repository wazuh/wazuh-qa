# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.logtest import (callback_logtest_started, callback_logtest_disabled,
                                   callback_configuration_error)
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
def test_configuration_file(get_configuration, configure_environment, restart_wazuh):
    """Check multiples logtest configuration
    """

    callback = None
    if 'valid_conf' in get_configuration['tags']:
        callback = callback_logtest_started
    elif 'disabled_conf' in get_configuration['tags']:
        callback = callback_logtest_disabled
    else:
        callback = callback_configuration_error

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback,
                            error_message='Event not found')
