# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_synchronization, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_disabled_sync_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

p, m = generate_params(extra_params={"TEST_DIRECTORIES": test_directories[0]})

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


def test_sync_disabled(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Verify that synchronization is disabled when enabled is set to no in the configuration.
    """
    # Check if the test should be skipped
    check_apply_test({'sync_disabled'}, get_configuration['tags'])

    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_synchronization)
        raise AttributeError(f'Unexpected event {event}')
