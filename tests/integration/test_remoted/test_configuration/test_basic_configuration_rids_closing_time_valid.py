# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.api as api
import wazuh_testing.remote as remote
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
    """

    """

    cfg = get_configuration['metadata']

    # Check that API query return the selected configuration
    for field in cfg.keys():
        api_answer = api.get_manager_configuration(section="remote", field=field)
        if field == 'protocol':
            array_protocol = np.array(cfg[field].split(","))
            assert (array_protocol == api_answer).all(), "Wazuh API answer different from introduced configuration"
        else:
            assert cfg[field] == api_answer, "Wazuh API answer different from introduced configuration"
