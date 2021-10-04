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
#test_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/force_options')
configurations_path = os.path.join(test_data_path, 'force_options_configuration.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)
tests = read_yaml(os.path.join(test_data_path, 'key_mismatch.yaml'))

# Variables
log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

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

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


@pytest.fixture(scope='function', params=tests)
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

def test_authd_force_options(configure_environment, override_wazuh_conf,
                       configure_sockets_environment, connect_to_sockets_module,
                       get_current_test_case, request):

    print(get_current_test_case['name'])
    print(get_current_test_case['description'])

    for stage in get_current_test_case['test_case']:
        print(stage['input'])
        print(stage['output'])

    assert True