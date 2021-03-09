# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.remote as remote
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

# Setting parameters for testing queue_size too big
parameters = [
    {'CONNECTION': 'syslog', 'PORT': '514', 'QUEUE_SIZE': '1200'}
]

metadata = [
    {'connection': 'syslog', 'port': '514', 'queue_size': '1200'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_queue_size",
                                           params=parameters,
                                           metadata=metadata)

configuration_ids = [f"{x['CONNECTION'], x['PORT'], x['QUEUE_SIZE']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_queue_size_syslog(get_configuration, configure_environment, restart_remoted):
    """Test if `wazuh-remoted` fails when `queue_size` tag is used at the same time that `syslog` connection.

    Raises:
        AssertionError: if `wazuh-remoted` doesn't respond error message.
    """
    log_callback = remote.callback_error_queue_size_syslog()
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
