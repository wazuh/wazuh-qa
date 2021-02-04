# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import random
import time
from ipaddress import IPv4Address
from secrets import token_hex

import pytest
import requests
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf

# Marks

pytestmark = pytest.mark.server

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

@pytest.mark.xfail(reason='To be deprecated in https://github.com/wazuh/wazuh/issues/7006')
@pytest.mark.parametrize('tags_to_apply', [
    {'bps_enabled'},
    {'bps_disabled'},
])
@pytest.mark.parametrize('insert_agent', [
    False,
    True,
])
def test_behind_proxy_server(insert_agent, tags_to_apply, get_configuration, configure_api_environment,
                             restart_api, wait_for_start, get_api_details):
    """State whether the behind_proxy_server option is working.

    Verify if the IP established in the X-Forwarded-For header of the request is
    used as the agent IP when the behind_proxy_server option is enabled.
    Otherwise, the registration IP should be different.

    The POST /agents and /agents/insert methods make use of this configuration,
    so both are tested in this  test.

    Parameters
    ----------
    insert_agent : bool
        Whether the endpoint to test is /agents/insert.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    behind_proxy_server = get_configuration['configuration']['behind_proxy_server']
    api_details = get_api_details()

    # Generate random IP and name.
    proxy_ip = str(IPv4Address(random.getrandbits(32)))
    data = {'name': token_hex(16)}

    # Extra data is needed when the endpoint /insert is used
    if insert_agent:
        data['id'] = str(random.randint(200, 2000))
        data['key'] = token_hex(32)

    # Add X-Forwarded-For.
    api_details['auth_headers']['X-Forwarded-For'] = proxy_ip
    api_details['base_url'] += '/agents'

    # Delete previous agents to avoid duplicate data error.
    delete_url = api_details['base_url'] + f"?agents_list=all&purge=true&status=&older_than=0s&status=all"
    delete_response = requests.delete(delete_url, headers=api_details['auth_headers'], verify=False)
    assert delete_response.status_code == 200, f'Delete response was not 200. Response: {delete_response.text}'

    # Add agent
    post_url = api_details['base_url'] + '/insert' if insert_agent else api_details['base_url']
    post_response = requests.post(post_url, json=data, headers=api_details['auth_headers'], verify=False)

    if post_response.status_code == 200:
        agent_id = post_response.json()['data']['id']

        # Get the agent to check its IP
        api_details['base_url'] += f"?agents_list={agent_id}"

        # It is necessary to wait a bit after adding the agent before querying it.
        retries = 0
        response_code = None
        while retries < 3 and response_code != 200:
            time.sleep(1)
            get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)
            response_code = get_response.status_code
            register_ip = get_response.json()['data']['affected_items'][0]['registerIP']
            retries += 1

        # Check if new agent has X-Forwarded-For IP or a different one.
        if behind_proxy_server:
            assert register_ip == proxy_ip, 'IP should be equal to the one in "X-Forwarded-For" header ' \
                                            f'({proxy_ip}), but it is not.'
        else:
            assert register_ip != proxy_ip, 'IP should not be equal to the one in "X-Forwarded-For" header, but it is.'

        # Delete the agent
        api_details['base_url'] += f"&purge=true&status=&older_than=0s&status=all"
        requests.delete(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    else:
        pytest.fail(f'There was a failure while trying to {"insert" if insert_agent else "add"} the agent, '
                    'so "behind_proxy_server" parameter could not be tested.'
                    f'Status code: {post_response.status_code}\n'
                    f'Full response: {post_response.text}')
