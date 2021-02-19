# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.agent_simulator import send_ping_pong_messages


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_socket_communication.yaml')

parameters = [
    {'PROTOCOL': 'UDP', 'CONNECTION': 'secure', 'PORT': 1514},
    {'PROTOCOL': 'UDP', 'CONNECTION': 'secure', 'PORT': 56000},
    {'PROTOCOL': 'TCP', 'CONNECTION': 'secure', 'PORT': 1514},
    {'PROTOCOL': 'TCP', 'CONNECTION': 'secure', 'PORT': 56000}
]

metadata = [
    {'protocol': 'UDP', 'connection': 'secure', 'port': 1514},
    {'protocol': 'UDP', 'connection': 'secure', 'port': 56000},
    {'protocol': 'TCP', 'connection': 'secure', 'port': 1514},
    {'protocol': 'TCP', 'connection': 'secure', 'port': 56000}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

def test_ping_pong_message(get_configuration, configure_environment):
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    control_service('restart', daemon='wazuh-remoted')
    config = get_configuration['metadata']

    log_callback = make_callback(
        fr"Started \(pid: \d+\). Listening on port {config['port']}\/{config['protocol']} \({config['connection']}\).",
        REMOTED_DETECTOR_PREFIX
    )

    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="Wazuh remoted didn't start as expected.")

    assert b'#pong' == send_ping_pong_messages(manager_address="localhost", protocol=config['protocol'],
                                               port=config['port'])

