# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.generic_callbacks as gc
import wazuh_testing.remote as remote
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'PROTOCOL': 'TCP', 'CONNECTION': 'secure', 'PORT': '99999'}
]
metadata = [
    {'protocol': 'TCP', 'connection': 'secure', 'port': '99999'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_port(get_configuration, configure_environment, restart_remoted):
    """Test if `wazuh-remoted` fails when invalid configuration for `port` label is set.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected error message.
    """
    cfg = get_configuration['metadata']

    log_callback = gc.callback_error_invalid_port(cfg['port'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
