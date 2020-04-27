# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import random
import socket
import ssl
import subprocess
import time
import yaml

from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf, write_wazuh_conf, load_wazuh_configurations
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.security import CertificateController
from wazuh_testing.tools.services import control_service, check_daemon_status
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

SSL_AGENT_CA = '/var/ossec/etc/test_rootCA.pem'
SSL_AGENT_CERT = '/tmp/test_sslagent.cert'
SSL_AGENT_PRIVATE_KEY = '/tmp/test_sslagent.key'
SSL_VERIFY_HOSTS = ['no', 'yes']
SIM_OPTIONS = ['NO CERT', 'VALID CERT', 'INCORRECT CERT', 'INCORRECT HOST']

AGENT_NAME = 'test_agent'
AGENT_IP = '127.0.0.1'
WRONG_IP = '10.0.0.240'
INPUT_MESSAGE = f"OSSEC A:'{AGENT_NAME}'"
OUPUT_MESSAGE = "OSSEC K:'"
# Ossec.conf configurations
params = [{
    'SSL_AGENT_CA' : SSL_AGENT_CA, 
    'SSL_VERIFY_HOST': ssl_verify_host,
} for ssl_verify_host in SSL_VERIFY_HOSTS for option in SIM_OPTIONS]
metadata = [{'sim_option' : option, 'verify_host' : ssl_verify_host } for ssl_verify_host in SSL_VERIFY_HOSTS for option in SIM_OPTIONS]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)
# Simulation options
# a. Unverified Host:
# - No certificate
# - Valid Certificate
# - Incorrect Certificate
# b. Verified Host:
# - No cerificate
# - No certificate
# - Valid Certificate
# - Incorrect Certificate
# - Valid certificate, Incorrect Host
# Variables
log_monitor_paths = []

receiver_sockets_params = [((AGENT_IP, 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-db', None, True), ('ossec-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="function")
def generate_ca_certificate(get_configuration):
    # Generate root key and certificate
    controller = CertificateController()
    option = get_configuration['metadata']['sim_option']
    if option not in ['NO_CERT']:
        # Wheter manager will recognize or not this key
        will_sign = True if option in ['VALID CERT', 'INCORRECT HOST'] else False
        controller.generate_agent_certificates(SSL_AGENT_PRIVATE_KEY, SSL_AGENT_CERT, WRONG_IP if option == 'INCORRECT HOST' else AGENT_IP, signed=will_sign)
    controller.store_ca_certificate(controller.get_root_ca_cert(), SSL_AGENT_CA)

# Tests

def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop')
    time.sleep(1)
    check_daemon_status(running=False)
     # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)
    # Start Wazuh daemons
    time.sleep(1)
    control_service('start')

    """Wait until agentd has begun"""
    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_agentd_startup)

def test_authd_ssl_certs(get_configuration, generate_ca_certificate):
    """
    """   
    verify_host = (get_configuration['metadata']['verify_host'] == 'yes')
    option = get_configuration['metadata']['sim_option']
    override_wazuh_conf(get_configuration)
    address, family, connection_protocol = receiver_sockets_params[0]
    SSL_socket = SocketController(address, family=family, connection_protocol=connection_protocol, open_at_start=False)
    if option != 'NO CERT':
        SSL_socket.set_ssl_configuration(certificate=SSL_AGENT_CERT, keyfile=SSL_AGENT_PRIVATE_KEY)
    try:
        SSL_socket.open()
        if option in ['NO CERT', 'INCORRECT CERT']:
            raise AssertionError(f'Agent was enable to connect without using any certificate or an incorrect one!')
    except ssl.SSLError as exception:
        if option in ['NO CERT','INCORRECT CERT']:
            # Expected to happen
            return
        else:
            raise AssertionError(f'Option {option} expected successfull socket connection but it failed')
    SSL_socket.send(INPUT_MESSAGE, size=False)
    try:
        response = ''
        while response == '':
            response = SSL_socket.receive().decode()
        if option in ['INCORRECT HOST'] and verify_host:
            raise AssertionError(f'An incorrect host was able to register using the verify_host option')
    except ConnectionResetError as exception:
        if option in ['INCORRECT HOST'] and verify_host:
            # Expected
            return
    assert response[:len(OUPUT_MESSAGE)] == OUPUT_MESSAGE, (f'Option {option} response from manager did not match expected')
    return
