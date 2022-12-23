import jsonschema
import os
import pytest

from wazuh_testing.api import make_api_call, get_api_details_dict
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import read_json_file
from wazuh_testing import event_monitor as evm
from wazuh_testing.agent import callback_connected_to_manager_ip, callback_connected_to_server
from wazuh_testing.tools import LOG_FILE_PATH

pytestmark = [pytest.mark.agent]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# ----------------------------------------------- TEST_STATISTICS_FORMAT -----------------------------------------------
# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_statistics_format.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_statistics_format.yaml')

# Statistics format test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_agent_statistics_format(configuration, metadata,   restart_wazuh_daemon_function ):
    """
    description: Check if the statistics returned by the API have the expected format.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Request the statistics of a particular daemon from the API.
            - Compare the obtained statistics with the json schema.
        - tierdown:
            - Restore initial configuration.

    wazuh_min_version: 4.4.0

    parameters:
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - get_api_details:
            type: fixture
            brief: Get API information.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service and truncate wazuh logs.

    assertions:
        - Check in the log that the EPS limitation has been activated.
        - Check that wazuh-analysisd daemon does not crash.

    input_description:
        - The `configuration_enabled` file provides the module configuration for this test.
        - The `cases_enabled` file provides the test cases.
    """
    connected_log = evm.check_event(callback=callback_connected_to_server(), file_to_monitor=LOG_FILE_PATH,
                                   timeout=30, error_message='The alert has not occurred').result()
    manager_ip = connected_log.group(1)
    endpoint = f"/manager/daemons/stats?daemons_list={metadata['endpoint']}"
    api_details = get_api_details_dict(host=manager_ip)
    response = make_api_call(manager_address=manager_ip, endpoint=endpoint, headers=api_details['auth_headers'])
    print(response.json())
    stats_schema = read_json_file(os.path.join(CONFIGURATIONS_PATH, f"{metadata['endpoint']}_template.json"))

    # Check if the API statistics response data meets the expected schema. Raise an exception if not.
    jsonschema.validate(instance=response.json(), schema=stats_schema)
