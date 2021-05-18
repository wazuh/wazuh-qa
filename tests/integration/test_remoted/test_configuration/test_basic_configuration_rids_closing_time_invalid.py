# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.generic_callbacks import callback_error_invalid_value_for
from wazuh_testing.tools.monitoring import REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '0s'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '4S'}
]

metadata = [
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '0'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '4S'}
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


def test_rids_closing_time_invalid(get_configuration, configure_environment, restart_remoted):
    """Test if `wazuh-remoted` fails when invalid `rids_closing_time` values are configured.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected error messages.
    """
    log_callback = callback_error_invalid_value_for('rids_closing_time', prefix=REMOTED_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
