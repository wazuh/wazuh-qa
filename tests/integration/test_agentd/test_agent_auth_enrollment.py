# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import subprocess
import yaml 

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.enrollment import EnrollmentSimulator
from wazuh_testing.tools.monitoring import QueueMonitor
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514
SERVER_KEY_PATH = '/etc/manager.key'
SERVER_CERT_PATH = '/etc/manager.cert'
INSTALLATION_FOLDER = '/var/ossec/bin/'


def load_tests(path):
    """ Loads a yaml file from a path 
    Retrun 
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))
params = [{'SERVER_ADDRESS': SERVER_ADDRESS,}]
metadata = [{}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

enrollment_server = EnrollmentSimulator(server_address=SERVER_ADDRESS, remoted_port=REMOTED_PORT, key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="module")
def configure_enrollment_server(request):
    enrollment_server.start()
    global monitored_sockets
    monitored_sockets = [QueueMonitor(x) for x in enrollment_server.queues]

    yield

    enrollment_server.shutdown()

@pytest.mark.parametrize('test_case', [case for case in tests])
def test_agent_auth_enrollment(configure_enrollment_server, configure_environment, test_case: list):
    print(f'Test: {test_case["name"]}')
    enrollment_server.clear()
    configuration = test_case.get('configuration', {})
    run_command = ['sudo', f'{INSTALLATION_FOLDER}agent-auth']
    run_command.append('-m')
    run_command.append(f'{SERVER_ADDRESS}')
    if configuration.get('agent_name'):
        run_command.append('-A')
        run_command.append(f'{configuration.get("agent_name")}')
    out = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = out.communicate()
    print(stdout)
    results = monitored_sockets[0].get_results(callback=(lambda y: [x.decode() for x in y]), timeout=1, accum_results=1)
    assert results[0] == test_case['enrollment']['expected_request'], 'Expected enrollment request message does not match'
    assert results[1] == test_case['enrollment']['response'], 'Expected response message does not match'
    return