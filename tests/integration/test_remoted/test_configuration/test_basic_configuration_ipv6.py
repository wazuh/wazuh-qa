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
    {'CONNECTION': 'secure'},
    {'CONNECTION': 'syslog'}
]

metadata = [
    {'connection': 'secure'},
    {'connection': 'syslog'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['CONNECTION']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_ipv6_secure(get_configuration, configure_environment, restart_remoted):
    """Check that when `ipv6` can be configured to `yes` without errors.

    In case of `secure` connection IPv4 should be used. Also, check if the API answer for
    manager connection coincides with the option selected on `manager.conf`.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected warning message or
        if API answer is different of expected configuration."""
    cfg = get_configuration['metadata']

    if cfg['connection'] == 'secure':
        log_callback = remote.callback_warning_secure_ipv6()
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    # Check that API query return the selected configuration
    remote.compare_config_api_response(cfg)
