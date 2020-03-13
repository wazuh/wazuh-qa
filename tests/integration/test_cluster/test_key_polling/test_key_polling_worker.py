# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.cluster import FERNET_KEY, master_simulator, cluster_msg_build, callback_clusterd_keypoll
from wazuh_testing.tools import WAZUH_PATH, CLUSTER_LOGS_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'cluster_conf.yaml')
params = [{'FERNET_KEY': FERNET_KEY}]
metadata = [{'fernet_key': FERNET_KEY}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

# Variables

log_monitor_paths = [CLUSTER_LOGS_PATH]
cluster_socket_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'cluster', 'c-internal.sock'))
cluster_socket_address = ('localhost', 1516)

receiver_sockets_params = [(cluster_socket_path, 'AF_UNIX', 'TCP')]  # SocketController items

mitm_master = ManInTheMiddle(address=cluster_socket_address, family='AF_INET', connection_protocol='TCP',
                             func=master_simulator)

# monitored_sockets_params is a list of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [('wazuh-clusterd', mitm_master, False)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


@pytest.mark.parametrize('cmd, counter, payload', [
    (b'run_keypoll', 1, b'{"message": "id:001"}'),
    (b'run_keypoll', 2, b'{"message": "ip:124.0.0.1"}')
])
def test_key_polling_worker(cmd, counter, payload, configure_environment, configure_mitm_environment,
                            detect_initial_worker_connected, connect_to_sockets_function):
    """
    Test worker behaviour with agent key-polling.

    Parameters
    ----------
    cmd : bytes
        Cluster message command
    counter : int
        Cluster message counter
    payload : bytes
        Cluster message payload data
    """
    # Build message to send to c-internal.sock in the worker, send it and consume the response
    message = cluster_msg_build(cmd, counter, payload, encrypt=False)
    receiver_sockets[0].send(message)

    try:
        result = monitored_sockets[0].start(timeout=5, callback=callback_clusterd_keypoll).result()
        assert result['payload'] == payload, f'Received payload in the master: {result["payload"]} ' \
                                             f'does not match expected payload: {payload}'
    except TimeoutError as e:
        raise e
