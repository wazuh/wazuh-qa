import os
import platform
import yaml
import pytest
import subprocess
import ssl
import time

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.security import CertificateController
from wazuh_testing.tools.file import load_tests


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_enrollment_conf.yaml')
tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))

# Default data

MANAGER_ADDRESS = '127.0.0.1'
MANAGER_PORT = 1515

folder = 'etc' if platform.system() == 'Linux' else ''
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, folder, 'client.keys')  # for unix add 'etc'
AUTHDPASS_PATH = os.path.join(WAZUH_PATH, folder, 'authd.pass')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'manager.cert')
SERVER_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'manager.pem')
AGENT_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'agent.key')
AGENT_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'agent.cert')
AGENT_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'agent.pem')
AGENT_AUTH_BINARY_PATH = '/var/ossec/bin/agent-auth' if platform.system() == 'Linux' else \
    os.path.join(WAZUH_PATH, 'agent-auth.exe')

CONFIG_PATHS = {
    'SERVER_PEM_PATH': SERVER_PEM_PATH,
    'AGENT_CERT_PATH': AGENT_CERT_PATH,
    'AGENT_PEM_PATH': AGENT_PEM_PATH,
    'AGENT_KEY_PATH': AGENT_KEY_PATH,
    'PASSWORD_PATH': AUTHDPASS_PATH
}


def parse_configuration_string(configuration):
    """Formats a configuration dictionary with the default CONFIG_PATHS.
    Args:
        Configuration (dict): Configuration dictionary to be extended with CONFIG_PATHS.
    """
    for key, value in configuration.items():
        if isinstance(value, str):
            configuration[key] = value.format(**CONFIG_PATHS)


@pytest.fixture(scope='module')
def create_certificates():
    cert_controller = CertificateController()
    cert_controller.get_root_ca_cert().sign(cert_controller.get_root_key(), cert_controller.digest)
    cert_controller.store_private_key(cert_controller.get_root_key(), AGENT_KEY_PATH)
    cert_controller.store_ca_certificate(cert_controller.get_root_ca_cert(), AGENT_CERT_PATH)


def configure_socket_listener(receiver_callback):
    """Configures the socket listener to start listening on the socket."""
    socket_listener = ManInTheMiddle(address=(MANAGER_ADDRESS, MANAGER_PORT), family='AF_INET',
                                     connection_protocol='SSL', func=receiver_callback)
    socket_listener.start()
    socket_listener.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2,
                                                   certificate=AGENT_CERT_PATH,
                                                   keyfile=AGENT_KEY_PATH,
                                                   options=None,
                                                   cert_reqs=ssl.CERT_OPTIONAL)

    while not socket_listener.queue.empty():
        socket_listener.queue.get_nowait()
    socket_listener.event.clear()

    return socket_listener


# Keys file

@pytest.mark.parametrize('test_case', [case for case in tests])
@pytest.fixture(scope='function')
def set_keys(test_case):
    """Writes the keys file with the content defined in the configuration.
    Args:
        test_case (dict): Current test case.
    """
    keys = test_case.get('pre_existent_keys', [])
    if keys:
        with open(CLIENT_KEYS_PATH, "w") as keys_file:
            for key in keys:
                keys_file.writelines(key)


# Password file

@pytest.mark.parametrize('test_case', [case for case in tests])
@pytest.fixture(scope='function')
def set_pass(test_case):
    """Writes the password file with the content defined in the configuration.
    Args:
        test_case (dict): Current test case.
    """
    with open(AUTHDPASS_PATH, "w") as f:
        if 'password_file_content' in test_case:
            f.write(test_case['password_file_content'])
