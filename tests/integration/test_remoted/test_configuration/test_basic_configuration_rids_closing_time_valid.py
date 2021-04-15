# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1s'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30s'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1m'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30m'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1h'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30h'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1d'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30d'}
]

metadata = [
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1s'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30s'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1m'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30m'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1h'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30h'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1d'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30d'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_rids_closing_time",
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['CONNECTION'], x['PORT'], x['RIDS_CLOSING_TIME']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_rids_closing_time_valid(get_configuration, configure_environment, restart_remoted):
    """Check that `rids_closing_time` option could be configured with valid values without errors.

    Check if the API answer for manager connection coincides with the option selected on `ossec.conf`.

    Raises:
        AssertionError: if API answer is different of expected configuration.
    """
    cfg = get_configuration['metadata']

    # Check that API query return the selected configuration
    api.compare_config_api_response(cfg, 'remote')
