import os
import pytest
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.authd import validate_authd_logs


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


# Tests

def test_authd_force_options_invalid_config(get_current_test_case, configure_local_internal_options_module,
                                            override_authd_force_conf, file_monitoring, restart_authd_function,
                                            tear_down):

   validate_authd_logs(get_current_test_case.get('log', []), log_monitor)
