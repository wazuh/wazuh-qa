import os
import pytest
import requests

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'configuration_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'configuration_test_module')

# --------------------------------------------- TEST_DEFAULT_CONFIGURATION ---------------------------------------------
# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_default_configuration.yaml')

# Default configuration test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)

expected_default_conf_response = {
    'request/remote': {
        'data': {'affected_items': [{'remote': [{'connection': 'secure', 'ipv6': 'no', 'protocol': ['TCP'],
                                                 'port': '1514', 'queue_size': '131072'}]}], 'total_affected_items': 1,
                 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    'request/global': {
        'data': {'affected_items': [{'global': {'remoted': {'agents_disconnection_alert_time': 0,
                                                            'agents_disconnection_time': 600}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    'analysis/active_response': {
        'data': {'affected_items': [{'active-response': []}], 'total_affected_items': 1,
                 'total_failed_items': 0, 'failed_items': []}, 'message': 'Active configuration was successfully read',
        'error': 0
    },
    'analysis/alerts': {
        'data': {'affected_items': [{'alerts': {'email_alert_level': 12, 'log_alert_level': 3}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    #'analysis/decoders':{
    #
    #},
    #'analysis/rules':{
    #
    #},
    'analysis/command': {
        'data': {'affected_items': [{'command': [{'name': 'disable-account', 'executable': 'disable-account',
                                                  'timeout_allowed': 1},
                                                 {'name': 'restart-wazuh', 'executable': 'restart-wazuh',
                                                  'timeout_allowed': 0},
                                                 {'name': 'firewall-drop', 'executable': 'firewall-drop',
                                                  'timeout_allowed': 1},
                                                 {'name': 'host-deny', 'executable': 'host-deny', 'timeout_allowed': 1},
                                                 {'name': 'route-null', 'executable': 'route-null',
                                                  'timeout_allowed': 1},
                                                 {'name': 'win_route-null', 'executable': 'route-null.exe',
                                                  'timeout_allowed': 1},
                                                 {'name': 'netsh', 'executable': 'netsh.exe', 'timeout_allowed': 1}]}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    #'agent/labels':{
    #
    #},
    'analysis/rule_test': {
        'data': {'affected_items': [{'rule_test': {'enabled': 'yes', 'threads': 1, 'max_sessions': 64,
                                                   'session_timeout': 900}}], 'total_affected_items': 1,
                                                   'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    'analysis/global': {
        'data': {'affected_items': [{'global': {'email_notification': 'no', 'logall': 'no', 'logall_json': 'no',
                                                'integrity_checking': 8, 'rootkit_detection': 8, 'host_information': 8,
                                                'prelude_output': 'no', 'zeromq_output': 'no', 'jsonout_output': 'yes',
                                                'alerts_log': 'yes', 'stats': 8, 'memory_size': 8192,
                                                'white_list': ['127.0.0.1', '10.0.2.3', 'localhost.localdomain'],
                                                'rotate_interval': 0, 'max_output_size': 0, 'eps': {'maximum': 0,
                                                'timeframe': 10}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    }
}

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
    },
    'analysis': {
        'data': {'affected_items': [{'internal': {'analysisd': {'debug': 0, 'default_timeframe': 360,
                                                                'stats_maxdiff': 999000, 'stats_mindiff': 1250,
                                                                'stats_percent_diff': 150, 'fts_list_size': 32,
                                                                'fts_min_size_for_str': 14, 'log_fw': 1,
                                                                'decoder_order_size': 256, 'label_cache_maxage': 10,
                                                                'show_hidden_labels': 0, 'rlimit_nofile': 458752,
                                                                'min_rotate_interval': 600}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    }
}

# --------------------------------------------- TEST_CUSTOM_CONFIGURATION ----------------------------------------------
# Configuration and cases data
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'custom_configuration.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_custom_configuration.yaml')

# Custom configuration test configurations (t3)
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_configurations_path, t3_configuration_parameters,
                                                t3_configuration_metadata)

expected_custom_conf_response = {
    'request/remote': {
        'data': {'affected_items': [{'remote': [{'connection': 'secure', 'ipv6': 'no', 'protocol': ['UDP'],
                                                 'port': '1514', 'queue_size': '131071'}]}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    'request/global': {
        'data': {'affected_items': [{'global': {'remoted': {'agents_disconnection_alert_time': 5,
                                                            'agents_disconnection_time': 300}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    'analysis/active_response': {
        'data': {'affected_items': [{'active-response': [{'command': 'restart-wazuh', 'timeout': 0, 'level': 0,
                                                          'location': 'ALL_AGENTS'}]}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    'analysis/alerts': {
        'data': {'affected_items': [{'alerts': {'email_alert_level': 6, 'log_alert_level': 5}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    #'analysis/decoders':{
    #
    #},
    #'analysis/rules':{
    #
    #},
    'analysis/command': {
        'data': {'affected_items': [{'command': [{'name': 'restart-wazuh', 'executable': 'restart-wazuh',
                                                  'timeout_allowed': 0}]}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    #'agent/labels':{
    #
    #},
    'analysis/rule_test': {
        'data': {'affected_items': [{'rule_test': {'enabled': 'no', 'threads': 1, 'max_sessions': 64,
                                                   'session_timeout': 900}}], 'total_affected_items': 1,
                                                   'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    },
    'analysis/global': {
        'data': {'affected_items': [{'global': {'email_notification': 'yes', 'logall': 'no', 'logall_json': 'no',
                                                'integrity_checking': 8, 'rootkit_detection': 8, 'host_information': 8,
                                                'prelude_output': 'no', 'zeromq_output': 'no', 'jsonout_output': 'yes',
                                                'alerts_log': 'yes', 'stats': 8, 'memory_size': 8192,
                                                'white_list': ['127.0.0.1', '10.0.2.3', 'localhost.localdomain'],
                                                'rotate_interval': 0, 'max_output_size': 0, 'eps': {'maximum': 0,
                                                'timeframe': 10}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    }
}


# ----------------------------------------- TEST_CUSTOM_INTERNAL_CONFIGURATION -----------------------------------------
# Configuration and cases data
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_custom_internal_configuration.yaml')

# Custom internal options test configurations (t4)
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
    },
    'analysis': {
        'data': {'affected_items': [{'internal': {'analysisd': {'debug': 2, 'default_timeframe': 360,
                                                                'stats_maxdiff': 999000, 'stats_mindiff': 1250,
                                                                'stats_percent_diff': 150, 'fts_list_size': 32,
                                                                'fts_min_size_for_str': 14, 'log_fw': 1,
                                                                'decoder_order_size': 256, 'label_cache_maxage': 10,
                                                                'show_hidden_labels': 1, 'rlimit_nofile': 458752,
                                                                'min_rotate_interval': 600}}}],
                 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
        'message': 'Active configuration was successfully read', 'error': 0
    }
}

local_internal_options = {'remoted.shared_reload': '20', 'remoted.request_timeout': '30',
                          'analysisd.show_hidden_labels': '1', 'analysisd.debug': '2'}


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('metadata', t1_configuration_metadata, ids=t1_case_ids)
def test_default_configuration(metadata, get_api_details):

    api_details = get_api_details()
    endpoint = metadata['endpoint']
    url = f"{api_details['base_url']}/manager/configuration/request/{endpoint}"
    response = requests.get(url, headers=api_details['auth_headers'], verify=False)

    assert response.json() == expected_default_conf_response[endpoint]


@pytest.mark.xfail(reason="It will be blocked by wazuh/wazuh#15694, when it is resolved, we can enable the test")
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('metadata', t2_configuration_metadata, ids=t2_case_ids)
def test_default_internal_configuration(metadata, get_api_details):

    endpoint = metadata['endpoint']
    api_details = get_api_details()
    url = f"{api_details['base_url']}/manager/configuration/{endpoint}/internal"
    response = requests.get(url, headers=api_details['auth_headers'], verify=False)

    assert response.json() == expected_default_internal_conf_response[endpoint]


@pytest.mark.tier(level=0)
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
@pytest.mark.parametrize('metadata', t4_configuration_metadata, ids=t4_case_ids)
def test_custom_internal_configuration(metadata, configure_local_internal_options_function, get_api_details,
                                       restart_wazuh_daemon_function):

    endpoint = metadata['endpoint']
    api_details = get_api_details()
    url = f"{api_details['base_url']}/manager/configuration/{endpoint}/internal"
    response = requests.get(url, headers=api_details['auth_headers'], verify=False)

    assert response.json() == expected_custom_internal_conf_response[endpoint]
