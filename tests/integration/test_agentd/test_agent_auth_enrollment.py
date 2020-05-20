# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import ssl
import subprocess
import yaml 

from OpenSSL import crypto, SSL
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.enrollment import EnrollmentSimulator
from wazuh_testing.tools.monitoring import QueueMonitor
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514
SERVER_KEY_PATH = '/etc/manager.key'
SERVER_CERT_PATH = '/etc/manager.cert'
SERVER_PEM_PATH = '/etc/manager.pem'
AGENT_KEY_PATH = '/etc/agent.key'
AGENT_CERT_PATH = '/etc/agent.cert'
AGENT_PEM_PATH = '/etc/agent.pem'
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
    if configuration.get('id'):
        enrollment_server.agent_id = configuration.get('id')
    if configuration.get('agent_name'):
        run_command.append('-A')
        run_command.append(f'{configuration.get("agent_name")}')
    if configuration.get('agent_address'):
        run_command.append('-I')
        run_command.append(f'{configuration.get("agent_address")}')
    if configuration.get('auto_negotiation') == 'yes':
        run_command.append('-a')
    if configuration.get('protocol') == 'TLSv1_1':
        enrollment_server.mitm_enrollment.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_1)
    else:
        enrollment_server.mitm_enrollment.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2)
    if configuration.get('ciphers'):
        run_command.append('-c')
        run_command.append(configuration.get('ciphers'))
    if configuration.get('check_certificate'):
        if configuration['check_certificate']['valid'] == 'yes':
            # Store valid certificate
            enrollment_server.cert_controller.store_ca_certificate(enrollment_server.cert_controller.get_root_ca_cert(), SERVER_PEM_PATH)
        else:
            # Create another certificate
            enrollment_server.cert_controller.generate_agent_certificates(AGENT_KEY_PATH, SERVER_PEM_PATH, configuration.get('agent_name'))
        run_command.append('-v')
        run_command.append(SERVER_PEM_PATH)
    if configuration.get('agent_certificate'):
        enrollment_server.mitm_enrollment.listener.set_ssl_configuration(cert_reqs=ssl.CERT_REQUIRED)
        enrollment_server.cert_controller.generate_agent_certificates(AGENT_KEY_PATH, AGENT_CERT_PATH, configuration.get('agent_name'), 
            signed=(configuration['agent_certificate']['valid'] == 'yes')
        )
            
        run_command.append('-k')
        run_command.append(AGENT_KEY_PATH)
        run_command.append('-x')
        run_command.append(AGENT_CERT_PATH)
    else:
        enrollment_server.mitm_enrollment.listener.set_ssl_configuration(cert_reqs=ssl.CERT_OPTIONAL)
    if configuration.get('use_source_ip'):
        run_command.append('-i')

    out = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = out.communicate()
    print(stdout.decode())
    results = monitored_sockets[0].get_results(callback=(lambda y: [x.decode() for x in y]), timeout=1, accum_results=1)
    if test_case.get('enrollment'):
        assert results[0] == test_case['enrollment']['expected_request'], 'Expected enrollment request message does not match'
        assert results[1] == test_case['enrollment']['response'], 'Expected response message does not match'
    else:
        assert len(results) == 0
    return