'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will verify if the `agent-key-polling` module works correctly in a cluster environment,
       specifically using a `master` node. This module allows retrieving the agent information from
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
    - https://documentation.wazuh.com/current/development/wazuh-cluster.html#master

tags:
    - key-polling
    - master
'''
import os
import re

import pytest
from wazuh_testing.cluster import FERNET_KEY, cluster_msg_build
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
modulesd_socket_path = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'krequest')
cluster_socket_address = ('localhost', 1516)

receiver_sockets_params = [(cluster_socket_address, 'AF_INET', 'TCP')]  # SocketController items

mitm_modules = ManInTheMiddle(address=modulesd_socket_path, family='AF_UNIX', connection_protocol='UDP')
# monitored_sockets_params is a List of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [('wazuh-clusterd', None, None), ('wazuh-modulesd', mitm_modules, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Functions


def callback_krequest(item):
    # Regex to match krequest socket received message being id:AGENT_VALID_ID or ip:AGENT_VALID_IP
    reg = r'^(id:[\d]{3}|ip:((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5]))'
    match = re.match(reg, item.decode())
    if match:
        return item.decode()


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.skip(reason='Development in progress: https://github.com/wazuh/wazuh/issues/4387')
@pytest.mark.parametrize('cmd, counter, payload, expected', [
    (b'run_keypoll', 1, b'{"message": "id:001"}', "id:001"),
    (b'run_keypoll', 2, b'{"message": "ip:124.0.0.1"}', "ip:124.0.0.1")
])
def test_key_polling_master(cmd, counter, payload, expected, configure_environment, configure_sockets_environment,
                            detect_initial_master_serving, connect_to_sockets_module, send_initial_worker_hello):
    '''
    description: Check if the Wazuh master node correctly handles the `agent-key-polling` module to retrieve
                 externally stored agent information. For this purpose, a simulated worker node is used
                 to send key-polling requests to the master node. After sending such requests, the test
                 checks if the socket managed by the `wazuh-modulesd` daemon has received them correctly.

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
        - expected:
            type: str
            brief: Expected message in krequest socket.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - detect_initial_master_serving:
            type: fixture
            brief: Make sure that the master node is serving after restarting the `wazuh-clusterd` daemon.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of the `connect_to_sockets` fixture.
        - send_initial_worker_hello:
            type: fixture
            brief: Send initial hello message to the master node.

    assertions:
        - Verify that the master node correctly receives key-polling messages by agent ID.
        - Verify that the master node correctly receives key-polling messages by agent IP address.

    input_description: Two test cases are found in the test module and include the requests
                       to be made and the expected result.

    expected_output:
        - r'id:001'
        - r'ip:124.0.0.1'

    tags:
        - keys
        - fernet
    '''
    # Build message and send it to the master
    message = cluster_msg_build(cmd=cmd, counter=counter, payload=payload, encrypt=True)
    receiver_sockets[0].send(message)

    # Ensure krequest socket (modulesd socket for key-polling) receives the appropriate data
    result = monitored_sockets[0].start(timeout=5, callback=callback_krequest).result()

    assert result == expected
