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
configurations_path = os.path.join(test_data_path, 'wazuh_syslog.yaml')

syslog_messages = {
    'dummy': "Syslog message sent by wazuh-qa to test remoted syslog",
    'sshd': remote.EXAMPLE_SYSLOG_EVENT,
    'sshd_pri_header': f"<1>{remote.EXAMPLE_SYSLOG_EVENT}",
    'multi_log': f"{remote.EXAMPLE_SYSLOG_EVENT}\n{remote.EXAMPLE_SYSLOG_EVENT}",
    'multi_log_pri_header': f"<1>{remote.EXAMPLE_SYSLOG_EVENT}\n<2>{remote.EXAMPLE_SYSLOG_EVENT}"
}

parameters = [
    {'PROTOCOL': 'UDP', 'PORT': 514},
    {'PROTOCOL': 'UDP', 'PORT': 51000},
    {'PROTOCOL': 'TCP', 'PORT': 514},
    {'PROTOCOL': 'TCP', 'PORT': 51000},
    {'PROTOCOL': 'udp', 'PORT': 514},
    {'PROTOCOL': 'udp', 'PORT': 51000},
    {'PROTOCOL': 'tcp', 'PORT': 514},
    {'PROTOCOL': 'tcp', 'PORT': 51000}
]

metadata = [
    {'protocol': 'UDP', 'port': 514},
    {'protocol': 'UDP', 'port': 51000},
    {'protocol': 'TCP', 'port': 514},
    {'protocol': 'TCP', 'port': 51000},
    {'protocol': 'udp', 'port': 514},
    {'protocol': 'udp', 'port': 51000},
    {'protocol': 'tcp', 'port': 514},
    {'protocol': 'tcp', 'port': 51000}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"syslog_{x['PROTOCOL']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize("syslog_message", syslog_messages.values())
def test_syslog_message(syslog_message, get_configuration, configure_environment, restart_wazuh):
    """Test if remoted can receive syslog messages with PRI header through the socket

    Raises:
        TimeoutError: if `wazuh-remoted` doesn't show the log message for syslog
    """
    config = get_configuration['metadata']
    port, protocol = config['port'], config['protocol']

    # Monitor the archives.log
    wazuh_archives_log_monitor = remote.create_archives_log_monitor()

    # Check if remoted correctly started with the new conf
    log_callback = remote.callback_detect_remoted_started(port=port, protocol=protocol, connection_type='syslog')
    wazuh_log_monitor.start(timeout=5, callback=log_callback, update_position=False,
                            error_message="Wazuh remoted didn't start as expected.")

    # Check if wazuh-remoted receives syslog messages
    remote.check_syslog_event(wazuh_archives_log_monitor, syslog_message, port, protocol)
