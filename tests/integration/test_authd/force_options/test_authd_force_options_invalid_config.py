import os
import pytest
import yaml
from wazuh_testing.tools.monitoring import make_callback, AUTHD_DETECTOR_PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, set_section_wazuh_conf, write_wazuh_conf, get_wazuh_conf
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.authd import create_authd_request, validate_authd_response, AUTHD_KEY_REQUEST_TIMEOUT, insert_pre_existent_agents


# Data paths
data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(data_path, 'template_configuration.yaml')
tests_path = os.path.join(data_path, 'test_cases', 'invalid_config')

# Configurations
configurations = load_wazuh_configurations(configurations_path, __name__)
local_internal_options = {'authd.debug': '2'}

# Tests
tests = []
test_case_ids = []
for file in os.listdir(tests_path):
    group_name = file.split(".")[0]
    file_tests = read_yaml(os.path.join(tests_path, file))
    tests = tests + file_tests
    test_case_ids = test_case_ids + [f"{group_name} {test_case['name']}" for test_case in file_tests]


# Functions
def validate_authd_logs(logs):
    for log in logs:
        log_monitor.start(timeout=AUTHD_KEY_REQUEST_TIMEOUT,
                          callback=make_callback(log, prefix=AUTHD_DETECTOR_PREFIX,
                                                 escape=True),
                          error_message=f"Expected error log does not occured: '{log}'")

def get_temp_force_config(param):
    """
    Creates a temporal config file.
    """
    temp = os.path.join(data_path, 'temp.yaml')
    force_conf = {'force': {'elements': []}}
    legacy_force_insert_conf = None
    for elem in param:
        if elem == 'force_insert':
            legacy_force_insert_conf = {'force_insert': {'value': param[elem]}}
        elif elem == 'disconnected_time':
            disconnected_time_conf = {'disconnected_time':{'value': 0, 'attributes':[{'enabled':'no'}]}}
            disconnected_time_conf['disconnected_time']['value'] = param[elem]['value']
            disconnected_time_conf['disconnected_time']['attributes'][0]['enabled'] = param[elem]['attributes'][0]['enabled']
            force_conf['force']['elements'].append(disconnected_time_conf)
        else:
            force_conf['force']['elements'].append({elem: {'value': param[elem]}})

    with open(configurations_path, 'r') as conf_file:
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(force_conf)
        if legacy_force_insert_conf:
            temp_conf_file[0]['sections'][0]['elements'].append(legacy_force_insert_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


# Fixtures

@pytest.fixture(scope='module')
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
def override_authd_force_conf(get_current_test_case, request):
    """
    Re-writes Wazuh configuration file with new configurations from the test case.
    """
    # Save current configuration
    backup_config = get_wazuh_conf()

    test_name = request.node.originalname
    configuration = get_current_test_case.get('configuration', {})
    # Configuration for testing
    temp = get_temp_force_config(configuration)
    conf = load_wazuh_configurations(temp, test_name, )
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)

    yield

    # Restore previous configuration
    write_wazuh_conf(backup_config)


# Tests

def test_authd_force_options_invalid_config(get_current_test_case, configure_local_internal_options_module,
                                            override_authd_force_conf, file_monitoring, restart_authd_function,
                                            tear_down):

   validate_authd_logs(get_current_test_case.get('log', []))
