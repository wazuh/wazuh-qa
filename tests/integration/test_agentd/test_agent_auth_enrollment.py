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
from conftest import DEFAULT_VALUES, SERVER_KEY_PATH, SERVER_CERT_PATH, \
        AgentAuthParser, build_expected_request, check_client_keys_file, \
        configure_enrollment
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514
AGENT_AUTH_BINARY_PATH = '/var/ossec/bin/agent-auth'
AUTHDPASS_PATH = '/var/ossec/etc/authd.pass'

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
    if 'agent-auth' in test_case.get("skips", []):
        pytest.skip("This test does not apply to agent-auth") 
    parser = AgentAuthParser(server_address=SERVER_ADDRESS, BINARY_PATH=AGENT_AUTH_BINARY_PATH, sudo=True)
    configuration = test_case.get('configuration', {})
    enrollment = test_case.get('enrollment', {})
    configure_enrollment(enrollment, enrollment_server, configuration.get('agent_name'))
    if configuration.get('agent_name'):
        parser.add_agent_name(configuration.get("agent_name"))
    if configuration.get('agent_address'):
        parser.add_agent_adress(configuration.get("agent_address"))
    if configuration.get('auto_method') == 'yes':
        parser.add_auto_negotiation()
    if configuration.get('ssl_cipher'):
        parser.add_ciphers(configuration.get('ssl_cipher'))
    if configuration.get('server_ca_path'):
        parser.add_manager_ca(configuration.get('server_ca_path'))
    if configuration.get('agent_key_path'):
        parser.add_agent_certificates(configuration.get('agent_key_path'), configuration.get('agent_certificate_path'))
    if configuration.get('use_source_ip'):
        parser.use_source_ip()
    if configuration.get('password'):
        parser.add_password(configuration['password']['value'], isFile=(configuration['password']['type'] == 'file'), path=AUTHDPASS_PATH)
    else:
        # Clears password file
        parser.add_password(None, isFile=True, path=AUTHDPASS_PATH)
    if configuration.get('groups'):
        parser.add_groups(configuration.get('groups'))

    out = subprocess.Popen(parser.get_command(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = out.communicate()
    print(stdout.decode())
    results = monitored_sockets[0].get_results(callback=(lambda y: [x.decode() for x in y]), timeout=1, accum_results=1)
    if test_case.get('enrollment') and test_case['enrollment'].get('response'):
        assert results[0] == build_expected_request(configuration), 'Expected enrollment request message does not match'
        assert results[1] == test_case['enrollment']['response'].format(**DEFAULT_VALUES), 'Expected response message does not match'
        assert check_client_keys_file(), 'Client key does not match'
    else:
        assert len(results) == 0
    return