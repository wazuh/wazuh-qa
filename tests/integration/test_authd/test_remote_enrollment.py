# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools import monitoring, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.sockets import wait_for_tcp_port
from wazuh_testing.tools.wazuh import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from contextlib import contextmanager

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

parameters = [
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'yes'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'yes'},
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'worker'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'worker'}
]

metadata = [
    {'remote_enrollment': 'no', 'node_type': 'no',  'id': 'no_remote_enrollment_standalone'},
    {'remote_enrollment': 'yes', 'node_type': 'no',  'id': 'yes_remote_enrollment_standalone'},
    {'remote_enrollment': 'no', 'node_type': 'master',  'id': 'no_remote_enrollment_cluster_master'},
    {'remote_enrollment': 'yes', 'node_type': 'master',  'id': 'yes_remote_enrollment_cluster_master'},
    {'remote_enrollment': 'no', 'node_type': 'worker',  'id': 'no_remote_enrollment_cluster_worker'},
    {'remote_enrollment': 'yes', 'node_type': 'worker', 'id': 'yes_remote_enrollment_cluster_worker'}
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

cluster_socket_address = ('localhost', 1516)
remote_enrollment_address = ('localhost', 1515)

@pytest.fixture(scope="module", params=configurations,
                ids=[f"{x['id']}" for x in metadata])
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@contextmanager
def not_raises(exception):
    try:
        yield
    except exception:
        raise pytest.fail("DID RAISE {0}".format(exception))


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
    expectation = not_raises(ConnectionRefusedError)
    expected_answer = 'OSSEC K:'

    test_metadata = get_configuration['metadata']
    remote_enrollment_enabled = test_metadata['remote_enrollment'] == 'yes'

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
        ssl_socket = SocketController(remote_enrollment_address, family='AF_INET', connection_protocol='SSL_TLSv1_2')

        ssl_socket.open()

        if test_metadata['node_type'] == 'worker':
            expected_answer = 'ERROR: Cannot comunicate with master'

        ssl_socket.send("OSSEC A:'user1'", size=False)
        response = ssl_socket.receive().decode()

        assert expected_answer in response

        ssl_socket.close()
