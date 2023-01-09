import os
import pytest

from wazuh_testing.api import make_api_call
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import read_yaml

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
EXPECTED_RESPONSES_PATH = os.path.join(TEST_DATA_PATH, 'expected_responses')

# --------------------------------------------- TEST_DEFAULT_CONFIGURATION ---------------------------------------------
# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_default_configuration.yaml')
t1_expected_responses_path = os.path.join(EXPECTED_RESPONSES_PATH, 'expected_responses_default_configuration.yaml')

# Default configuration test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)

# ---------------------------------------- TEST_DEFAULT_INTERNAL_CONFIGURATION -----------------------------------------
# Configuration and cases data
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_default_internal_configuration.yaml')
t2_expected_responses_path = os.path.join(EXPECTED_RESPONSES_PATH, 'expected_responses_default_internal_conf.yaml')

# Default internal test configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)

# --------------------------------------------- TEST_CUSTOM_CONFIGURATION ----------------------------------------------
# Configuration and cases data
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_custom.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_custom_configuration.yaml')
t3_expected_responses_path = os.path.join(EXPECTED_RESPONSES_PATH, 'expected_responses_custom_configuration.yaml')

# Custom configuration test configurations (t3)
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_configurations_path, t3_configuration_parameters,
                                                t3_configuration_metadata)

# ----------------------------------------- TEST_CUSTOM_INTERNAL_CONFIGURATION -----------------------------------------
# Configuration and cases data
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_custom_internal_configuration.yaml')
t4_expected_responses_path = os.path.join(EXPECTED_RESPONSES_PATH, 'expected_responses_custom_internal_conf.yaml')

# Custom internal configuration test configurations (t4)
t4_configuration_parameters, t4_configuration_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)

local_internal_options = {'remoted.shared_reload': '20', 'remoted.request_timeout': '30'}


@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', t1_configuration_metadata, ids=t1_case_ids)
def test_default_configuration(metadata, get_api_details, restart_wazuh_daemon):

    api_details = get_api_details()
    endpoint = metadata['endpoint']
    url = f"/manager/configuration/{endpoint}"
    response = make_api_call(endpoint=url, headers=api_details['auth_headers'])
    expected_response = read_yaml(t1_expected_responses_path)

    assert response.json() == expected_response[endpoint]


@pytest.mark.xfail(reason="It will be blocked by wazuh/wazuh#15694, when it is resolved, we can enable the test")
@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', t2_configuration_metadata, ids=t2_case_ids)
def test_default_internal_configuration(metadata, get_api_details, restart_wazuh_daemon):

    endpoint = metadata['endpoint']
    api_details = get_api_details()
    url = f"/manager/configuration/{endpoint}/internal"
    response = make_api_call(endpoint=url, headers=api_details['auth_headers'])
    expected_response = read_yaml(t2_expected_responses_path)

    assert response.json() == expected_response[endpoint]


@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_custom_configuration(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                              get_api_details, restart_wazuh_daemon_function):

    api_details = get_api_details()
    for endpoint in metadata['endpoints']:
        url = f"/manager/configuration/{endpoint}"
        response = make_api_call(endpoint=url, headers=api_details['auth_headers'])
        expected_response = read_yaml(t3_expected_responses_path)

        assert response.json() == expected_response[endpoint]


@pytest.mark.xfail(reason="It will be blocked by wazuh/wazuh#15694, when it is resolved, we can enable the test")
@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', t4_configuration_metadata, ids=t4_case_ids)
def test_custom_internal_configuration(metadata, configure_local_internal_options_function, get_api_details,
                                       restart_wazuh_daemon_function):

    endpoint = metadata['endpoint']
    api_details = get_api_details()
    url = f"/manager/configuration/{endpoint}/internal"
    response = make_api_call(endpoint=url, headers=api_details['auth_headers'])
    expected_response = read_yaml(t4_expected_responses_path)

    assert response.json() == expected_response[endpoint]
