import jsonschema
import os
import pytest

from wazuh_testing.api import make_api_call
from wazuh_testing.tools import agent_simulator as ag
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import read_json_file
from wazuh_testing.tools.wazuh_manager import remove_agents

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
STATISTICS_TEMPLATE_PATH = os.path.join(TEST_DATA_PATH, 'statistics_template')

# ------------------------------------------- TEST_MANAGER_STATISTICS_FORMAT -------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_manager_statistics_format.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'manager_statistics_format_test_module',
                             'cases_manager_statistics_format.yaml')
t1_statistics_template_path = os.path.join(STATISTICS_TEMPLATE_PATH, 'manager_statistics_format_test_module')

# Manager statistics format test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# -------------------------------------------- TEST_AGENT_STATISTICS_FORMAT --------------------------------------------
# Configuration and cases data
t2_cases_path = os.path.join(TEST_CASES_PATH, 'agent_statistics_format_test_module',
                             'cases_agent_statistics_format.yaml')
t2_statistics_template_path = os.path.join(STATISTICS_TEMPLATE_PATH, 'agent_statistics_format_test_module')

# Agent statistics format test configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)


@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_manager_statistics_format(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                                   get_api_details, restart_wazuh_daemon_function):
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
        - Check if the statistics returned by the API have the expected format.

    input_description:
        - The `configuration_manager_statistics_format` file provides the module configuration for this test.
        - The `cases_manager_statistics_format` file provides the test cases.
    """
    endpoint = f"/manager/daemons/stats?daemons_list={metadata['endpoint']}"
    api_details = get_api_details()
    response = make_api_call(endpoint=endpoint, headers=api_details['auth_headers'])
    stats_schema = read_json_file(os.path.join(t1_statistics_template_path, f"{metadata['endpoint']}_template.json"))

    # Check if the API statistics response data meets the expected schema. Raise an exception if not.
    jsonschema.validate(instance=response.json(), schema=stats_schema)


@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', t2_configuration_metadata, ids=t2_case_ids)
def test_agent_statistics_format(metadata, restart_wazuh_daemon_function, get_api_details):
    """
    description: Check if the statistics returned by the API have the expected format.

    test_phases:
        - setup:
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Simulate and connect an agent.
            - Request the statistics of a particular daemon and agent from the API.
            - Compare the obtained statistics with the json schema.
            - Stop and delete the simulated agent.

    wazuh_min_version: 4.4.0

    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - get_api_details:
            type: fixture
            brief: Get API information.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service and truncate wazuh logs.

    assertions:
        - Check if the statistics returned by the API have the expected format.

    input_description:
        - The `cases_agent_statistics_format` file provides the test cases.
    """
    agents = ag.create_agents(1, 'localhost')
    sender, injector = ag.connect(agents[0])

    endpoint = f"/agents/{agents[0].id}/daemons/stats?daemons_list={metadata['endpoint']}"
    api_details = get_api_details()
    response = make_api_call(endpoint=endpoint, headers=api_details['auth_headers'])
    stats_schema = read_json_file(os.path.join(t2_statistics_template_path, f"{metadata['endpoint']}_template.json"))

    # Check if the API statistics response data meets the expected schema. Raise an exception if not.
    jsonschema.validate(instance=response.json(), schema=stats_schema)

    # Stop and delete simulated agent
    injector.stop_receive()
    remove_agents(agents[0].id, 'api')
