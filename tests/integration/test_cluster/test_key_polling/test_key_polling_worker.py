'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will verify if the `agent-key-polling` module works correctly in a cluster environment,
       specifically using a `worker` node. This module allows retrieving the agent information from
       an external database, like `MySQL` or any database engine, for registering it to the `client.keys` file.

tier: 0

modules:
    - cluster

components:
    - manager

daemons:
    - wazuh-authd
    - wazuh-clusterd
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/agent-key-polling.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-agent-key-polling.html
    - https://documentation.wazuh.com/current/user-manual/configuring-cluster/basics.html
    - https://documentation.wazuh.com/current/development/wazuh-cluster.html#worker

tags:
    - key-polling
    - worker
'''
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


@pytest.mark.skip(reason='Development in progress: https://github.com/wazuh/wazuh/issues/4387')
@pytest.mark.parametrize('cmd, counter, payload', [
    (b'run_keypoll', 1, b'{"message": "id:001"}'),
    (b'run_keypoll', 2, b'{"message": "ip:124.0.0.1"}')
])
def test_key_polling_worker(cmd, counter, payload, configure_environment, configure_sockets_environment,
                            detect_initial_worker_connected, connect_to_sockets_function):
    '''
    description: Check if the Wazuh worker node correctly forwards agent key-polling requests to the master node.
                 For this purpose, a simulated master node is used to receive key-polling requests from the worker node.
                 After sending such requests, the test checks if the master node has received them correctly.

    wazuh_min_version: 4.2

    parameters:
        - cmd:
            type: bytes
            brief: Cluster message command.
        - counter:
            type: int
            brief: Cluster message counter.
        - payload:
            type: bytes
            brief: Cluster message payload data.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - detect_initial_worker_connected:
            type: fixture
            brief: Make sure that the worker node is connected to master one
                   after restarting the `wazuh-clusterd` daemon.
        - connect_to_sockets_function:
            type: fixture
            brief: Function scope version of the `connect_to_sockets` fixture.

    assertions:
        - Verify that the master node correctly receives the payload of key-polling by agent ID.
        - Verify that the master node correctly receives the payload of key-polling by agent IP address.

    input_description: Two test cases are found in the test module and include the requests
                       to be made and the expected result.

    expected_output:
        - The payload of key-polling by agent ID (001) in the body response.
        - The payload of key-polling by agent IP address (124.0.0.1) in the body response.

    tags:
        - keys
    '''
    # Build message to send to c-internal.sock in the worker and send it
    message = cluster_msg_build(cmd=cmd, counter=counter, payload=payload, encrypt=False)
    receiver_sockets[0].send(message)

    try:
        result = monitored_sockets[0].start(timeout=5, callback=callback_clusterd_keypoll).result()
        assert result['payload'] == payload, f'Received payload in the master: {result["payload"]} ' \
                                             f'does not match expected payload: {payload}'
    except TimeoutError as e:
        raise e
