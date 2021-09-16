'''
brief: This module verifies the correct behavior of the agent-auth enrollment tool under different configurations
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
metadata:
    component:
        - Agent
    modules:
        - agent-auth
    daemons:
        - agent-auth
    operating_system:
        - Ubuntu
        - CentOS
        - Windows
    tiers:
        - 0
    tags:
        - Enrollment
        - Agent-auth
'''

import pytest
import os
import platform
import subprocess

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import load_tests
from wazuh_testing.tools.monitoring import QueueMonitor, make_callback
from wazuh_testing.tools.utils import get_host_name
from wazuh_testing.agent import AgentAuthParser
from wazuh_testing.tools import WAZUH_PATH

AGENT_AUTH_BINARY_PATH = '/var/ossec/bin/agent-auth' if platform.system() == 'Linux' else \
    os.path.join(WAZUH_PATH, 'agent-auth.exe')

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
tests_path =  os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml')
configurations_path = os.path.join(test_data_path, 'wazuh_enrollment_conf.yaml')
tests = load_tests(tests_path)
configurations = load_wazuh_configurations(configurations_path, __name__)
MANAGER_ADDRESS = '127.0.0.1'
AGENT_AUTH_TIMEOUT = 10

def launch_agent_auth(configuration):
    """Launches agent-auth based on a specific dictionary configuration

    Args:
        configuration (dict): Dictionary with the agent-auth configuration.
    """
    parser = AgentAuthParser(server_address=MANAGER_ADDRESS, BINARY_PATH=AGENT_AUTH_BINARY_PATH,
                             sudo=True if platform.system() == 'Linux' else False)
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
        parser.add_password(configuration.get('password'))
    if configuration.get('groups'):
        parser.add_groups(configuration.get('groups'))

    out = subprocess.Popen(parser.get_command(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out.communicate()

# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope='function', params=tests)
def get_current_test_case(request):
    """Get current test case from the module"""
    return request.param


@pytest.fixture(scope='module')
def shutdown_agentd():
    control_service('stop', daemon='wazuh-agentd')


def test_agent_auth_enrollment(configure_environment, shutdown_agentd, get_current_test_case, create_certificates,
                               set_keys, set_pass, file_monitoring, configure_socket_listener, request):
    """
        test_logic:
            "Check that different configuration generates the adequate enrollment message or the corresponding
            error log. Agent-auth will be executed using the different parameters and with different keys and password
            files scenarios as described in the test cases."
        checks:
            - The enrollment message is sent when the configuration is valid
            - The enrollment message is generated as expected when the configuration is valid.
            - The error log is generated as expected when the configuration is invalid.
    """
    if 'agent-auth' in get_current_test_case.get('skips', []):
        pytest.skip('This test does not apply to agent-auth')

    if 'expected_error' in get_current_test_case:
        launch_agent_auth(get_current_test_case.get('configuration', {}))

        log_monitor = request.module.log_monitor
        if get_current_test_case.get('expected_fail'):
            with pytest.raises(TimeoutError):
                log_monitor.start(timeout=AGENT_AUTH_TIMEOUT,
                                  callback=make_callback(get_current_test_case.get('expected_error'), prefix='.*', escape=True))
        else:
            log_monitor.start(timeout=AGENT_AUTH_TIMEOUT,
                            callback=make_callback(get_current_test_case.get('expected_error'), prefix='.*', escape=True),
                            error_message='Expected error log does not occured')

    else:
        test_expected = get_current_test_case['message']['expected'].format(host_name=get_host_name()).encode()
        test_response = get_current_test_case['message']['response'].format(host_name=get_host_name()).encode()
        # Monitor MITM queue
        socket_monitor = QueueMonitor(request.module.socket_listener.queue)
        event = (test_expected, test_response)

        launch_agent_auth(get_current_test_case.get('configuration', {}))

        try:
            # Start socket monitoring
            socket_monitor.start(timeout=AGENT_AUTH_TIMEOUT, callback=lambda received_event: event == received_event,
                                 error_message='Enrollment request message never arrived', update_position=False)
        finally:
            socket_monitor.stop()
