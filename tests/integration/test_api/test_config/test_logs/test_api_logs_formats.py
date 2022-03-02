import os
import pytest
import yaml

from wazuh_testing.tools import PREFIX, API_LOG_FILE_PATH, API_JSON_LOG_FILE_PATH
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.monitoring import FileMonitor, make_callback
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# Variables

daemons_handler_configuration = {'daemons': ['wazuh-apid']}
test_directories = [os.path.join(PREFIX, 'test_logs')]
log_file_monitor = FileMonitor(API_LOG_FILE_PATH)
json_log_file_monitor = FileMonitor(API_JSON_LOG_FILE_PATH)

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
logs_path = os.path.join(test_data_path, 'logs.yaml')
with open(logs_path) as f:
    test_cases = yaml.safe_load(f)
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
@pytest.mark.parametrize('tags_to_apply', [{'logs_plain'}, {'logs_json'}, {'logs_json_plain'}])
def test_api_logs_formats(test_case: list, tags_to_apply: list, get_configuration, configure_api_environment,
                          daemons_handler):
    check_apply_test(tags_to_apply, get_configuration['tags'])

    current_test_case = test_case[1]
    if test_case[0]['level'] == 'ERROR':
        control_service('start', daemon=daemons_handler_configuration['daemons'][0])

    json_log_file_monitor.start(timeout=15, callback=make_callback(current_test_case['output'], prefix=''),
                               error_message='The log was not the expected.').result()
