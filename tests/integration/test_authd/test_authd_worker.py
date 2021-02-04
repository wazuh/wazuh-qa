# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess
import time

import pytest
import yaml
from wazuh_testing.cluster import FERNET_KEY, CLUSTER_DATA_HEADER_SIZE, cluster_msg_build
from wazuh_testing.tools import WAZUH_PATH, CLUSTER_LOGS_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

def load_tests(path):
    """ Loads a yaml file from a path
    Retrun
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)


class WorkerMID(ManInTheMiddle):

    def __init__(self, address, family='AF_UNIX', connection_protocol='TCP', func: callable = None):
        self.cluster_input = None
        self.cluster_output = None
        super().__init__(address, family, connection_protocol, self.verify_message)

    def set_cluster_messages(self, cluster_input, cluster_output):
        self.cluster_input = cluster_input
        self.cluster_output = cluster_output

    def verify_message(self, data: bytes):
        if len(data) > CLUSTER_DATA_HEADER_SIZE:
            message = data[CLUSTER_DATA_HEADER_SIZE:]
            response = cluster_msg_build(cmd=b'send_sync', counter=2, payload=bytes(self.cluster_output.encode()),
                                         encrypt=False)
            print(f'Received message from wazuh-authd: {message}')
            print(f'Response to send: {self.cluster_output}')
            self.pause()
            return response
        else:
            raise ConnectionResetError('Invalid cluster message!')

    def pause(self):
        self.event.set()

    def restart(self):
        self.event.clear()


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = load_tests(os.path.join(test_data_path, 'worker_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
params = [{'FERNET_KEY': FERNET_KEY}]
metadata = [{'fernet_key': FERNET_KEY}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

# Variables
log_monitor_paths = [CLUSTER_LOGS_PATH]
cluster_socket_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'cluster', 'c-internal.sock'))
ossec_authd_socket_path = ("localhost", 1515)
receiver_sockets_params = [(ossec_authd_socket_path, 'AF_INET', 'SSL_TLSv1_2')]

mitm_master = WorkerMID(address=cluster_socket_path, family='AF_UNIX', connection_protocol='TCP')

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True),
                            ('wazuh-clusterd', mitm_master, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Tests

@pytest.fixture(scope="function", params=message_tests)
def set_up_groups(request):
    groups = request.param.get('groups', [])
    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])
    yield request.param
    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


def test_ossec_auth_messages(get_configuration, set_up_groups, configure_environment, configure_sockets_environment,
                             connect_to_sockets_module, wait_for_agentd_startup):
    """Check that every input message in authd port generates the adequate output

    Parameters
    ----------
    test_case : list
        List of test_case stages (dicts with input, output and stage keys).
    """
    test_case = set_up_groups['test_case']
    for stage in test_case:
        # Push expected info to mitm queue
        mitm_master.set_cluster_messages(stage['cluster_input'], stage['cluster_output'])
        # Reopen socket (socket is closed by maanger after sending message with client key)
        mitm_master.restart()
        receiver_sockets[0].open()
        expected = stage['port_output']
        message = stage['port_input']
        receiver_sockets[0].send(stage['port_input'], size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        clusterd_queue = monitored_sockets[0]
        # callback lambda function takes out tcp header and decodes binary to string
        results = clusterd_queue.get_results(callback=(lambda y: [x[CLUSTER_DATA_HEADER_SIZE:].decode() for x in y]),
                                             timeout=1, accum_results=1)
        assert response[:len(expected)] == expected, \
            'Failed test case {}: Response was: {} instead of: {}'.format(set_up_groups['name'], response, expected)
        # Assert monitored sockets
        assert results[0] == stage['cluster_input'], 'Expected clusterd input message does not match'
        assert results[1] == stage['cluster_output'], 'Expected clusterd output message does not match'
