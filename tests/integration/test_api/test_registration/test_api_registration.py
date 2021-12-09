'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

'''
import os
import pytest
import yaml
import requests
import time
import re
import ipaddress
from wazuh_testing.tools.configuration import load_wazuh_configurations

from wazuh_testing.api import get_api_details_dict
from wazuh_testing.tools import CLIENT_KEYS_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.wazuh_manager import remove_all_agents


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
api_registration_requets_file = os.path.join(test_data_path, 'tcases.yaml')
daemons_handler_configuration = {'all_daemons': True}
api_registration_requests = []
with open(api_registration_requets_file) as tcases:
    api_registration_requests = yaml.load(tcases)

expected_json_ipv6_not_valid = {'error': 1}

parameters = [
    {'IPV6': 'yes'},
    {'IPV6': 'no'}
]
metadata = [
    {'ipv6': 'yes'},
    {'ipv6': 'no'},
]

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['ipv6']}" for x in metadata]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

def retrieve_client_key_entry(agent_parameters):
    with open(CLIENT_KEYS_PATH) as client_keys_file:
        client_keys_content = client_keys_file.readlines()
        client_keys_dictionary = []
        for entry in client_keys_content:
            client_key_agent_list = entry.split()

            client_key_agent_dict = {}
            client_key_agent_dict.update({'id': client_key_agent_list[0], 'name': client_key_agent_list[1], 
                                          'ip': client_key_agent_list[2], 'key': client_key_agent_list[3]})

            client_keys_dictionary.append(client_key_agent_dict)

    desired_entries = []
    for client_keys_entry_dict in client_keys_dictionary:
        if agent_parameters.items() <= client_keys_entry_dict.items():
            desired_entries.append(agent_parameters)
    return desired_entries


@pytest.fixture(scope="module")
def clean_registered_agents():
    truncate_file(CLIENT_KEYS_PATH)
    time.sleep(10)
    remove_all_agents('manage_agents')
    time.sleep(5)

    yield

    remove_all_agents('manage_agents')


def check_valid_agent_id(id):
    return re.match("(^[0-9][0-9][0-9]$)", id)


def check_valid_agent_key(key):
    return len(key) > 0


def check_api_data_response(api_response, expected_response):
    api_response_error = api_response['error']
    assert api_response_error == expected_response['error']

    if api_response_error == 0:
        if 'key' in expected_response['data']:
            assert check_valid_agent_key(api_response['data']['key'])
            del api_response['data']['key']
            del expected_response['data']['key']

        if 'id' in expected_response['data']:
            assert check_valid_agent_id(api_response['data']['id']) 
            del api_response['data']['id']
            del expected_response['data']['id']

    return  api_response == expected_response


@pytest.mark.parametrize("api_registration_parameters", api_registration_requests)
def test_agentd_server_configuration(api_registration_parameters, get_configuration, configure_environment, 
                                     restart_and_wait_api, clean_registered_agents):

    for stage in range(len(api_registration_parameters['parameters'])):

        request_parameters = api_registration_parameters['parameters'][stage]
        expected = api_registration_parameters['expected'][stage]
        registration_ip_ipv6 = api_registration_parameters['parameters'][stage]['ipv6']


        api_details = get_api_details_dict()
        api_query = f"{api_details['base_url']}/agents?"

        expected_client_keys_ip = request_parameters['agent_ip']
        if api_registration_parameters['parameters'][stage]['ipv6']:
            expected_client_keys_ip = ipaddress.IPv6Address(request_parameters['agent_ip']).exploded 

        expected_client_keys_entry = {'name': request_parameters['agent_name'],
                                      'ip':  expected_client_keys_ip}
        request_json = {'name': request_parameters['agent_name'],
                        'ip':  request_parameters['agent_ip']}

        response = requests.post(api_query, headers=api_details['auth_headers'], json=request_json,
                                 verify=False)

        if get_configuration['metadata']['ipv6'] == 'no' and registration_ip_ipv6:
            assert check_api_data_response(response.json(), expected_json_ipv6_not_valid)
        else:
            # Assert response is the same specified in the api_registration_parameters
            assert check_api_data_response(response.json(), expected['json'])
        
        # Ensure client keys is updated
        if response.json()['error'] == 0:
            assert retrieve_client_key_entry(expected_client_keys_entry)
