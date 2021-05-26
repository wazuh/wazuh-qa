# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
from contextlib import nullcontext as does_not_raise

from wazuh_testing.tools import monitoring, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.sockets import wait_for_tcp_port
from wazuh_testing.tools.wazuh import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

parameters = [
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'yes'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'yes'},
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'worker'},
    # x{'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'worker'},
]

metadata = [
    {'remote_enrollment': 'no', 'id': 'no_remote_enrollment_standalone'},
    {'remote_enrollment': 'yes', 'id': 'yes_remote_enrollment_standalone'},
    {'remote_enrollment': 'no', 'id': 'no_remote_enrollment_cluster_master'},
    {'remote_enrollment': 'yes', 'id': 'yes_remote_enrollment_cluster_master'},
    {'remote_enrollment': 'no', 'id': 'no_remote_enrollment_cluster_worker'},

    # {'remote_enrollment': 'yes', 'id': 'yes_remote_enrollment_cluster_worker}
    # this fails with 'ERROR: Cannot communicate with master', would require a master node to work
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


@pytest.fixture(scope="module", params=configurations,
                ids=[f"{x['id']}" for x in metadata])
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


def test_remote_enrollment(get_configuration, configure_environment, restart_authd):
    """Check that Authd remote enrollment is enabled/disabled according to the configuration.

    By default, remote enrollment is enabled. When disabled, Authd TLS port (1515 by default) won't be listening
    to new connection, but requests to local socket will still be attended.

    Raises:
        TimeoutError: if the expected logs do not appear or the port 1515 is not available when it should.
        ConnectionRefusedError: if remote enrollment is enabled but authd refuse external connections.
        assertRaises: if the expected OSSEC K message doesn't appear in authd response when remote connection
                      are enabled.
    """
    expectation = does_not_raise()

    configuration = get_configuration['metadata']
    remote_enrollment_enabled = configuration['remote_enrollment'] == 'yes'

    if remote_enrollment_enabled:
        expected_log = "Accepting connections on port 1515. No password required."
        wait_for_tcp_port(1515)
    else:
        expected_log = ".*Port 1515 was set as disabled.*"
        expectation = pytest.raises(ConnectionRefusedError)

    FileMonitor(LOG_FILE_PATH).start(timeout=5,
                                     callback=monitoring.make_callback(pattern=expected_log,
                                                                       prefix=monitoring.AUTHD_DETECTOR_PREFIX),
                                     error_message=f'Expected log not found: {expected_log}')
    with expectation:
        ssl_socket = SocketController(("localhost", 1515), family='AF_INET', connection_protocol='SSL_TLSv1_2')

        ssl_socket.open()

        ssl_socket.send("OSSEC A:'user1'", size=False)
        response = ssl_socket.receive().decode()

        assert "OSSEC K:'" in response

        ssl_socket.close()

