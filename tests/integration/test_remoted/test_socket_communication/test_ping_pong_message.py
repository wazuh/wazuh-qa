# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.remote import callback_detect_remoted_started, send_ping_pong_messages
from wazuh_testing.tools.configuration import load_wazuh_configurations


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_socket_communication.yaml')

parameters = [
    {'PROTOCOL': 'UDP', 'PORT': 1514},
    {'PROTOCOL': 'UDP', 'PORT': 56000},
    {'PROTOCOL': 'TCP', 'PORT': 1514},
    {'PROTOCOL': 'TCP', 'PORT': 56000},
    {'PROTOCOL': 'UDP,TCP', 'PORT': 1514},
    {'PROTOCOL': 'UDP,TCP', 'PORT': 56000},
    {'PROTOCOL': 'TCP,UDP', 'PORT': 1514},
    {'PROTOCOL': 'TCP,UDP', 'PORT': 56000},
    {'PROTOCOL': 'TCP,TCP', 'PORT': 1514},
    {'PROTOCOL': 'UDP,UDP', 'PORT': 1514},
    {'PROTOCOL': 'TCP,TCP', 'PORT': 56000},
    {'PROTOCOL': 'UDP,UDP', 'PORT': 56000},
]

metadata = [
    {'protocol': 'UDP', 'port': 1514},
    {'protocol': 'UDP', 'port': 56000},
    {'protocol': 'TCP', 'port': 1514},
    {'protocol': 'TCP', 'port': 56000},
    {'protocol': 'UDP,TCP', 'port': 1514},
    {'protocol': 'UDP,TCP', 'port': 56000},
    {'protocol': 'TCP,UDP', 'port': 1514},
    {'protocol': 'TCP,UDP', 'port': 56000},
    {'protocol': 'TCP,TCP', 'port': 1514},
    {'protocol': 'UDP,UDP', 'port': 1514},
    {'protocol': 'TCP,TCP', 'port': 56000},
    {'protocol': 'UDP,UDP', 'port': 56000},
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_ping_pong_message(get_configuration, configure_environment, restart_remoted):
    """Test if wazuh-remoted sends the #pong message

    Raises:
        AssertionError: if `wazuh-remoted` doesn't respond `#pong`
    """
    config = get_configuration['metadata']

    test_multiple_pings = False

    if config['protocol'] in ['TCP,UDP', 'UDP,TCP']:
        protocol, test_multiple_pings = "TCP,UDP", True
    elif config['protocol'] in ['TCP,TCP', 'UDP,UDP']:
        protocol = config['protocol'].split(',')[0]
    else:
        protocol = config['protocol']

    log_callback = callback_detect_remoted_started(port=config['port'], protocol=protocol)

    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="Wazuh remoted didn't start as expected.")

    if test_multiple_pings:
        assert b'#pong' == send_ping_pong_messages(manager_address="localhost", protocol='UDP', port=config['port'])
        assert b'#pong' == send_ping_pong_messages(manager_address="localhost", protocol='TCP', port=config['port'])
    else:
        assert b'#pong' == send_ping_pong_messages(manager_address="localhost", protocol=protocol, port=config['port'])

