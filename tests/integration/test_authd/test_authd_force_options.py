import os
import shutil
import subprocess
import time

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.file import truncate_file, read_yaml
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'etc', 'client.keys')

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/force_options')
configurations_path = os.path.join(test_data_path, 'force_options_configuration.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)
tests = read_yaml(os.path.join(test_data_path, 'key_mismatch.yaml'))
tests2 = read_yaml(os.path.join(test_data_path, 'after_registration_time.yaml'))
tests3 = read_yaml(os.path.join(test_data_path, 'disconnected_time.yaml'))

for i in range(len(tests2)):
    tests.append(tests2[i])

for i in range(len(tests3)):
    tests.append(tests3[i])

# Variables
log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


configuration_ids = ['authd_force_options']
test_case_ids = [f"{test_case['name']}" for test_case in tests]

# Functions

def get_temp_yaml(param):
    """
    Creates a temporal config file.
    """
    temp = os.path.join(test_data_path, 'temp.yaml')
    with open(configurations_path, 'r') as conf_file:
        force_conf = {'force': {'elements': []}}
        for elem in param:
            if elem == 'disconnected_time':
                disconnected_time_conf = {'disconnected_time':{'value': 0, 'attributes':[{'enabled':'no'}]}}
                disconnected_time_conf['disconnected_time']['value'] = param[elem]['value']
                disconnected_time_conf['disconnected_time']['attributes'][0]['enabled'] = param[elem]['attributes'][0]['enabled']
                force_conf['force']['elements'].append(disconnected_time_conf)
            else:
                force_conf['force']['elements'].append({elem: {'value': param[elem]}})
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(force_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


# Fixtures

@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


@pytest.fixture(scope='function', params=tests, ids=test_case_ids)
def get_current_test_case(request):
    """
    Get current test case from the module
    """
    return request.param

@pytest.fixture(scope='function')
def override_wazuh_conf(get_current_test_case, request):
    """
    Re-writes Wazuh configuration file with new configurations from the test case.
    """
    test_name = request.node.originalname
    configuration = get_current_test_case.get('configuration', {})
    #parse_configuration_string(configuration)
    # Configuration for testing
    temp = get_temp_yaml(configuration)
    conf = load_wazuh_configurations(temp, test_name, )
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)


# Tests

def test_authd_force_options(configure_environment, override_wazuh_conf,clean_client_keys_file_function,
                       configure_sockets_environment_function, connect_to_sockets_function,
                       get_current_test_case, request):

    print(get_current_test_case['name'])
    print(get_current_test_case['description'])

    for stage in get_current_test_case['test_case']:
        print(stage['input'])
        print(stage['output'])

        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['output']
        message = stage['input']
        receiver_sockets[0].send(stage['input'], size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        assert response[:len(expected)] == expected, \
            'Failed test case {}: Response was: {} instead of: {}'.format(get_current_test_case['name'], response, expected)

    assert True