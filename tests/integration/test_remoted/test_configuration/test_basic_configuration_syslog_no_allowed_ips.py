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
    {'CONNECTION': 'syslog'}
]
metadata = [
    {'connection': 'syslog'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['CONNECTION']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_allowed_denied_ips_syslog(get_configuration, configure_environment, restart_remoted):
    """Test if `wazuh-remoted` fails when `syslog` connection is configured without `allowed-ips` value.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected error message.
    """
    log_callback = remote.callback_info_no_allowed_ips()
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
