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
    {'PROTOCOL': 'Testing,UDP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'Testing,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,UDP,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'Testing,UDP', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP,Testing', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'Testing,Testing', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP,UDP,Testing', 'CONNECTION': 'syslog', 'PORT': '514'}
]
metadata = [
    {'protocol': 'Testing,UDP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'Testing,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,UDP,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'Testing,UDP', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP,Testing', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'Testing,Testing', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP,UDP,Testing', 'connection': 'syslog', 'port': '514'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_protocol(get_configuration, configure_environment, restart_remoted):
    """
    """

    cfg = get_configuration['metadata']
    protocol_field = cfg['protocol'].split(',')

    valid_invalid_protocols = remote.get_protocols(protocol_field)

    valid_protocol = valid_invalid_protocols[0]
    invalid_protocol_list = valid_invalid_protocols[1]

    for invalid_protocol in invalid_protocol_list:
        log_callback = remote.callback_ignored_invalid_protocol(invalid_protocol)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    if len(valid_protocol) == 0:
        log_callback = remote.callback_error_getting_protocol()
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    elif len(valid_protocol) == 1:
        log_callback = remote.callback_detect_remoted_started(cfg['port'], valid_protocol[0], cfg['connection'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    else:
        used_protocol = 'TCP,UDP'
        if cfg['connection'] == 'syslog':
            used_protocol = 'TCP'
        log_callback = remote.callback_detect_remoted_started(cfg['port'], used_protocol, cfg['connection'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    # Check that API query return the selected configuration
    remote.compare_config_api_response(cfg)
