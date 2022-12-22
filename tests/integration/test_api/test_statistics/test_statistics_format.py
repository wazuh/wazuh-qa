import jsonschema
import os
import pytest
import requests

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import read_json_file

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'statistics_format_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'statistics_format_test_module')

# ----------------------------------------------- TEST_STATISTICS_FORMAT -----------------------------------------------
# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_statistics_format.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_statistics_format.yaml')

# Statistics format test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_enabled(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                 get_api_details, restart_wazuh_daemon_function):

    endpoint = metadata['endpoint']
    api_details = get_api_details()
    url = f"{api_details['base_url']}/manager/daemons/stats?daemons_list={endpoint}"
    response = requests.get(url, headers=api_details['auth_headers'], verify=False)
    stats_schema = read_json_file(os.path.join(CONFIGURATIONS_PATH, f'{endpoint}_template.json'))

    jsonschema.validate(instance=response.json(), schema=stats_schema)
