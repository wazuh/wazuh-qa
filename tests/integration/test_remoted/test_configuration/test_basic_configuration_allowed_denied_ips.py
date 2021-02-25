# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time
import socket
import wazuh_testing.api as api

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.monitoring import make_callback, REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
configurations_path = os.path.join(test_data_path, 'data', 'wazuh_basic_configuration.yaml')

parameters = [
    {'ALLOWED': '127.0.0.0/24','DENIED': '127.0.0.1'}
]

metadata = [
    {'allowed-ips': '127.0.0.0/24','denied-ips': '127.0.0.1'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['ALLOWED']}   _{x['DENIED']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_allowed_denied_ips_syslog(get_configuration, configure_environment):
    """
    Checks that "allowed-ips" and "denied-ips" could be configured without errors for syslog connection
    """
    cfg = get_configuration['metadata']

    time.sleep(1)

    log_callback = make_callback(
        fr"Remote syslog allowed from: \'{cfg['allowed-ips']}\'",
        REMOTED_DETECTOR_PREFIX
    )

    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="Wazuh remoted didn't start as expected.")


    localhost='127.0.0.1'


    time.sleep(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = 'Feb 22 13:08:48 Remoted Syslog Denied testing'
    sock.sendto(data.encode(), (localhost, 514))
    sock.close()

    time.sleep(1)
    log_callback = make_callback(
        fr"Message from \'{cfg['denied-ips']}\' not allowed. Cannot find the ID of the agent.",
        REMOTED_DETECTOR_PREFIX
    )


    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="The expected output for denied-ips has not been produced")

    # Check that API query return the selected configuration
    for field in cfg.keys():
        api_answer = api.get_manager_configuration(section='remote', field=field)
        assert cfg[field] == api_answer, "Wazuh API answer different from introduced configuration"

