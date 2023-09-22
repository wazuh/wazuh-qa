import os
import platform
import yaml
import pytest
import ssl
import socket

from wazuh_testing.tools import WAZUH_PATH, CLIENT_KEYS_PATH, get_version
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.security import CertificateController
from wazuh_testing.tools.utils import get_host_name
from wazuh_testing.tools.configuration import load_wazuh_configurations, set_section_wazuh_conf, write_wazuh_conf

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_enrollment_conf.yaml')

# Default data

MANAGER_ADDRESS = '127.0.0.1'
MANAGER_PORT = 1515

folder = 'etc' if platform.system() == 'Linux' else ''
AUTHDPASS_PATH = os.path.join(WAZUH_PATH, folder, 'authd.pass')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'manager.cert')
SERVER_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'manager.pem')
AGENT_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'agent.key')
AGENT_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'agent.cert')
AGENT_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'agent.pem')

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
    """
    Writes the certificate files used for SSL communication.
    """
    cert_controller = CertificateController()
    cert_controller.get_root_ca_cert().sign(cert_controller.get_root_key(), cert_controller.digest)
    cert_controller.store_private_key(cert_controller.get_root_key(), AGENT_KEY_PATH)
    cert_controller.store_ca_certificate(cert_controller.get_root_ca_cert(), AGENT_CERT_PATH)


@pytest.fixture(scope='function')
def configure_socket_listener(request, get_current_test_case):
    """
    Configures the socket listener to start listening on the socket.
    """
    socket_listener_opened = True
    if 'message' in get_current_test_case and 'response' in get_current_test_case['message']:
        response = get_current_test_case['message']['response'].format(host_name=get_host_name()).encode()
    else:
        response = "".encode()
    if 'message' in get_current_test_case and 'expected' in get_current_test_case['message']:
        expected = get_current_test_case['message']['expected'].format(host_name=get_host_name(),
                                                                       agent_version=get_version()).encode()
    else:
        expected = None
    address_family = 'AF_INET6' if 'ipv6' in get_current_test_case else 'AF_INET'
    manager_address = '::1' if 'ipv6' in get_current_test_case else MANAGER_ADDRESS

    address_family = 'AF_INET6' if 'ipv6' in get_current_test_case else 'AF_INET'
    manager_address = '::1' if 'ipv6' in get_current_test_case else MANAGER_ADDRESS

    def receiver_callback(received_event):
        return response if not expected or expected == received_event else "".encode()

    try:
        socket_listener = ManInTheMiddle(address=(manager_address, MANAGER_PORT), family=address_family,
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

        setattr(request.module, 'socket_listener', socket_listener)

    except Exception:
        print("Unexpected exception occurred during Man In the Middle initialization")
        socket_listener_opened = False

    yield socket_listener_opened

    socket_listener.shutdown()


# Keys file

@pytest.fixture(scope='function')
def set_keys(get_current_test_case):
    """
    Writes the keys file with the content defined in the configuration.
    Args:
        get_current_test_case (dict): Current test case.
    """
    keys = get_current_test_case.get('pre_existent_keys', [])
    if keys:
        with open(CLIENT_KEYS_PATH, "w") as keys_file:
            for key in keys:
                keys_file.writelines(key)


# Password file

@pytest.fixture(scope='function')
def set_password(get_current_test_case):
    """Writes the password file with the content defined in the configuration.
    Args:
        get_current_test_case (dict): Current test case.
    """
    with open(AUTHDPASS_PATH, "w") as f:
        if 'password_file_content' in get_current_test_case:
            f.write(get_current_test_case['password_file_content'])


# Wazuh conf

def get_temp_yaml(param):
    """
    Creates a temporal config file.
    """
    temp = os.path.join(test_data_path, 'temp.yaml')
    with open(configurations_path, 'r') as conf_file:
        enroll_conf = {'enrollment': {'elements': []}}
        for elem in param:
            if elem == 'password':
                continue
            enroll_conf['enrollment']['elements'].append({elem: {'value': param[elem]}})
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(enroll_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


@pytest.fixture(scope='function')
def override_wazuh_conf(get_current_test_case, request):
    """
    Re-writes Wazuh configuration file with new configurations from the test case.
    """
    test_name = request.node.originalname
    configuration = get_current_test_case.get('configuration', {})
    parse_configuration_string(configuration)
    # Configuration for testing
    temp = get_temp_yaml(configuration)
    conf = load_wazuh_configurations(temp, test_name, )
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)
