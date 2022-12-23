import os
import pytest
import requests

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data


pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# --------------------------------------------- TEST_DEFAULT_CONFIGURATION ---------------------------------------------
# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_default_configuration.yaml')

# Default configuration test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)

#expected_default_conf_response = {
#    'remote': {
#        'data': {'affected_items': [{'remote': [{'connection': 'secure', 'ipv6': 'no', 'protocol': ['TCP'],
#                 'port': '1514', 'queue_size': '131072'}]}], 'total_affected_items': 1, 'total_failed_items': 0,
#                 'failed_items': []}, 'message': 'Active configuration was successfully read', 'error': 0
#    },
#    'global': {
#        'data': {'affected_items': [{'global': {'remoted': {'agents_disconnection_alert_time': 0,
#                 'agents_disconnection_time': 600}}}], 'total_affected_items': 1, 'total_failed_items': 0,
#                 'failed_items': []}, 'message': 'Active configuration was successfully read', 'error': 0
#    }
#}

# ---------------------------------------- TEST_DEFAULT_INTERNAL_CONFIGURATION -----------------------------------------
# Configuration and cases data
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_default_internal_configuration.yaml')

# Default internal test configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)

expected_default_internal_conf_response = {
    'request': {
        'data': {'affected_items': [{'internal': {'remoted': {'recv_counter_flush': 128, 'comp_average_printout': 19999,
                                                              'verify_msg_id': 0, 'recv_timeout': 1,
                                                              'pass_empty_keyfile': 1, 'sender_pool': 8,
                                                              'request_pool': 8, 'request_rto_sec': 1,
                                                              'request_rto_msec': 0, 'max_attempts': 4,
                                                              'request_timeout': 10, 'response_timeout': 60,
                                                              'shared_reload': 10, 'rlimit_nofile': 16384,
                                                              'merge_shared': 1, 'guess_agent_group': 0,
                                                              'receive_chunk': 4096, 'send_chunk': 4096,
                                                              'buffer_relax': 1, 'send_buffer_size': 131072,
                                                              'send_timeout_to_retry': 1, 'tcp_keepidle': 30,
                                                              'tcp_keepintvl': 10, 'tcp_keepcnt': 3}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    }
}

# --------------------------------------------- TEST_CUSTOM_CONFIGURATION ----------------------------------------------
# Configuration and cases data
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_custom.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_custom_configuration.yaml')

# Enabled test configurations (t3)
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_configurations_path, t3_configuration_parameters,
                                                t3_configuration_metadata)

expected_custom_conf_response = {
    'remote': {
        'data': {'affected_items': [{'remote': [{'connection': 'secure', 'ipv6': 'no', 'protocol': ['UDP'],
                 'port': '1514', 'queue_size': '131071'}]}], 'total_affected_items': 1, 'total_failed_items': 0,
                 'failed_items': []}, 'message': 'Active configuration was successfully read', 'error': 0
    },
    'global': {
        'data': {'affected_items': [{'global': {'remoted': {'agents_disconnection_alert_time': 5,
                 'agents_disconnection_time': 300}}}], 'total_affected_items': 1, 'total_failed_items': 0,
                 'failed_items': []}, 'message': 'Active configuration was successfully read', 'error': 0
    }
}

daemons_handler_configuration = {'daemons': ['wazuh-remoted']}


# ----------------------------------------- TEST_CUSTOM_INTERNAL_CONFIGURATION -----------------------------------------
# Configuration and cases data
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_custom_internal_configuration.yaml')

# Enabled test configurations (t3)
t4_configuration_parameters, t4_configuration_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)

expected_custom_internal_conf_response = {
    'request': {
        'data': {'affected_items': [{'internal': {'remoted': {'recv_counter_flush': 128, 'comp_average_printout': 19999,
                                                              'verify_msg_id': 0, 'recv_timeout': 1,
                                                              'pass_empty_keyfile': 1, 'sender_pool': 8,
                                                              'request_pool': 8, 'request_rto_sec': 1,
                                                              'request_rto_msec': 0, 'max_attempts': 4,
                                                              'request_timeout': 30, 'response_timeout': 60,
                                                              'shared_reload': 20, 'rlimit_nofile': 16384,
                                                              'merge_shared': 1, 'guess_agent_group': 0,
                                                              'receive_chunk': 4096, 'send_chunk': 4096,
                                                              'buffer_relax': 1, 'send_buffer_size': 131072,
                                                              'send_timeout_to_retry': 1, 'tcp_keepidle': 30,
                                                              'tcp_keepintvl': 10, 'tcp_keepcnt': 3}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    }
}

local_internal_options = {'remoted.shared_reload': '20', 'remoted.request_timeout': '30'}
daemons_handler_configuration = {'daemons': ['wazuh-remoted']}


@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', t1_configuration_metadata, ids=t1_case_ids)
def test_default_configuration(metadata, get_api_details):

    api_details = get_api_details()
    endpoint = metadata['endpoint']
    url = f"{api_details['base_url']}/manager/configuration/request/{endpoint}"
    response = requests.get(url, headers=api_details['auth_headers'], verify=False)

    assert response.json() == metadata['expected_response']


@pytest.mark.xfail(reason="It will be blocked by wazuh/wazuh#15694, when it is resolved, we can enable the test")
@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', t2_configuration_metadata, ids=t2_case_ids)
def test_default_internal_configuration(metadata, get_api_details):

    endpoint = metadata['endpoint']
    api_details = get_api_details()
    url = f"{api_details['base_url']}/manager/configuration/{endpoint}/internal"
    response = requests.get(url, headers=api_details['auth_headers'], verify=False)

    assert response.json() == expected_default_internal_conf_response[endpoint]


@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_custom_configuration(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                              get_api_details, restart_wazuh_daemon_function):

    api_details = get_api_details()
    for endpoint in expected_custom_conf_response:
        url = f"{api_details['base_url']}/manager/configuration/request/{endpoint}"
        response = requests.get(url, headers=api_details['auth_headers'], verify=False)

        assert response.json() == expected_custom_conf_response[endpoint]


@pytest.mark.xfail(reason="It will be blocked by wazuh/wazuh#15694, when it is resolved, we can enable the test")
@pytest.mark.tier(level=0)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', t4_configuration_metadata, ids=t4_case_ids)
def test_custom_internal_configuration(metadata, configure_local_internal_options_function, get_api_details,
                                       restart_wazuh_daemon_function):

    endpoint = metadata['endpoint']
    api_details = get_api_details()
    url = f"{api_details['base_url']}/manager/configuration/{endpoint}/internal"
    response = requests.get(url, headers=api_details['auth_headers'], verify=False)

    assert response.json() == expected_custom_internal_conf_response[endpoint]
