import os

import pytest
from wazuh_testing.tools import PREFIX, API_LOG_FILE_PATH, API_JSON_LOG_FILE_PATH
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.server

# Variables

daemons_handler_configuration = {'daemons': ['wazuh-apid']}
test_directories = [os.path.join(PREFIX, 'test_logs')]
log_file_monitor = FileMonitor(API_LOG_FILE_PATH)
json_log_file_monitor = FileMonitor(API_JSON_LOG_FILE_PATH)

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [{'logs_plain'}, {'logs_json'}, {'logs_json_plain'}])
def test_logs_format(tags_to_apply, get_configuration, configure_api_environment, daemons_handler):

    check_apply_test(tags_to_apply, get_configuration['tags'])
    pass
