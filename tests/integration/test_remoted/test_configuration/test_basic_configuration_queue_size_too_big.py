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
    {'CONNECTION': 'secure', 'PORT': '1514', 'QUEUE_SIZE': '99999999'}
]

metadata = [
    {'connection': 'secure', 'port': '1514', 'queue_size': '99999999'}
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


def test_big_queue_size(get_configuration, configure_environment, restart_remoted):
    """Test if warning message appears in case `queue_size` is greater than 262144.

    Check that the API answer for manager connection coincides with the option selected on `manager.conf`.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected warning messages or if API answer is
        different of expected configuration.
    """
    cfg = get_configuration['metadata']

    log_callback = remote.callback_queue_size_too_big()
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    remote.compare_config_api_response(cfg)
