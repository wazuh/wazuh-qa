import os
import platform
import socket
import yaml

from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
import subprocess
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.configuration import set_section_wazuh_conf, write_wazuh_conf

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

DEFAULT_VALUES = {
    'enabled': 'yes',
    'manager_address': '127.0.0.1',
    'port': 1515,
    'host_name': socket.gethostname(),
    'groups': None,
    'agent_address': '127.0.0.1',
    'use_source_ip': 'no',
    'ssl_cipher': None,
    'server_ca_path': None,
    'agent_certificate_path': None,
    'agent_key_path': None,
    'authorization_pass_path': None
}

folder = 'etc' if platform.system() == 'Linux' else ''

CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, folder, 'client.keys')  # for unix add 'etc'
AUTHDPASS_PATH = os.path.join(WAZUH_PATH, folder, 'authd.pass')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'manager.cert')
SERVER_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'manager.pem')
AGENT_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'agent.key')
AGENT_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'agent.cert')
AGENT_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'agent.pem')
AUTHDPASS_PATH = os.path.join(WAZUH_PATH, folder, 'authd.pass')
AGENT_AUTH_BINARY_PATH = '/var/ossec/bin/agent-auth' if platform.system() == 'Linux' else \
    os.path.join(WAZUH_PATH, 'agent-auth.exe')

CONFIG_PATHS = {
    'SERVER_PEM_PATH': SERVER_PEM_PATH,
    'AGENT_CERT_PATH': AGENT_CERT_PATH,
    'AGENT_PEM_PATH': AGENT_PEM_PATH,
    'AGENT_KEY_PATH': AGENT_KEY_PATH,
    'PASSWORD_PATH': AUTHDPASS_PATH
}

def load_tests(path):
    """ Loads a yaml file from a path
    Returns
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)


def parse_configuration_string(configuration):
    for key, value in configuration.items():
        if isinstance(value, str):
            configuration[key] = value.format(**CONFIG_PATHS)
class AgentAuthParser:
    def __init__(self, server_address=None, BINARY_PATH='/var/ossec/bin/agent-auth', sudo=False):
        self._command = []
        if sudo:
            self._command.append('sudo')
        self._command += [BINARY_PATH]
        if server_address:
            self._command += ['-m', server_address]

    def get_command(self):
        return self._command

    def add_agent_name(self, agent_name):
        self._command += ['-A', agent_name]

    def add_agent_adress(self, agent_adress):
        self._command += ['-I', agent_adress]

    def add_auto_negotiation(self):
        self._command += ['-a']

    def add_ciphers(self, ciphers):
        self._command += ['-c', ciphers]

    def add_agent_certificates(self, key, cert):
        self._command += ['-k', key, '-x', cert]

    def add_manager_ca(self, ca_cert):
        self._command += ['-v', ca_cert]

    def use_source_ip(self):
        self._command += ['-i']

    def add_password(self, password):
        self._command += ['-P', password]

    def add_groups(self, group_string):
        self._command += ['-G', group_string]

def launch_agent_auth(configuration):
    parse_configuration_string(configuration)
    parser = AgentAuthParser(server_address=DEFAULT_VALUES['manager_address'], BINARY_PATH=AGENT_AUTH_BINARY_PATH,
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

def wait_until(x, log_str):
    """Callback function to wait for a message in a log file.

    Args:
        x (str): String containing message.
        log_str (str): Log file string.
    """
    return x if log_str in x else None

LAST_MESSAGE = None
CURRENT_TEST_CASE = {}

def receiver_callback(received):
    if len(received) == 0:
        return b""

    global LAST_MESSAGE
    LAST_MESSAGE = received.decode()
    response = CURRENT_TEST_CASE['message']['response'].format(**DEFAULT_VALUES).encode()
    return response

def get_last_message():
    global LAST_MESSAGE
    import time
    timeout = time.time() + 20 # 20 seconds timeout
    while not LAST_MESSAGE and time.time() <= timeout:
        pass
    return LAST_MESSAGE

def clear_last_message():
    global LAST_MESSAGE
    LAST_MESSAGE = None

def clean_log_file():
    try:
        client_file = open(LOG_FILE_PATH, 'w')
        client_file.close()
    except IOError as exception:
        raise

def get_temp_yaml(param):
    temp = os.path.join(test_data_path, 'temp.yaml')
    with open(configurations_path, 'r') as conf_file:
        enroll_conf = {'enrollment': {'elements': []}}
        for elem in param:
            if elem == 'password':
                continue
            enroll_conf['enrollment']['elements'].append({elem: {'value': param[elem]}})
        print(enroll_conf)
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(enroll_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp

def override_wazuh_conf(configuration, test):
    parse_configuration_string(configuration)
    # Configuration for testing
    temp = get_temp_yaml(configuration)
    conf = load_wazuh_configurations(temp, test, )
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)
