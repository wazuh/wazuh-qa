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

parameters = [
    {'CONNECTION': 'secure', 'PORT': '1514', 'QUEUE_SIZE': '1'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'QUEUE_SIZE': '1200'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'QUEUE_SIZE': '262144'}
]

metadata = [
    {'connection': 'secure', 'port': '1514', 'queue_size': '1'},
    {'connection': 'secure', 'port': '1514', 'queue_size': '1200'},
    {'connection': 'secure', 'port': '1514', 'queue_size': '262144'}
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


def test_queue_size_valid(get_configuration, configure_environment, restart_remoted):
    """Check that `queue_size` option could be configured with valid values (any number between 1 and 262144) without
    errors.

    Check if the API answer for manager connection coincides with the option selected on `manager.conf` and expected
    warning message is shown in `ossec.log`.

    Raises:
        AssertionError: if API answer is different of expected configuration.
    """
    cfg = get_configuration['metadata']

    remote.compare_config_api_response(cfg)
