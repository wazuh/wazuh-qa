# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

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

@pytest.mark.parametrize('tags_to_apply', [
    {'config1'},
    {'config2'}
])
def test_block_time(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                               wait_for_start, get_api_details):
    """Check that the blocking time for IPs detected as brute-force attack works.
   
    Provoke a block, make a request before the blocking 
    time finishes and one after the blocking time.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    host = get_configuration['conf']['host']
    port = get_configuration['conf']['port']
    block_time = get_configuration['conf']['block_time']
    max_login_attempts = get_configuration['conf']['max_login_attempts']
    

    # PUT configuration for security.yaml
    api_details = get_api_details()
    data = {'block_time': block_time}
    data['max_login_attempts'] = max_login_attempts
    data['max_request_per_minute'] = 300   # for a different test
    put_response = requests.put(api_details['base_url'] + '/security/config', json=data, headers=api_details['auth_headers'], verify=False)
    assert put_response.status_code == 200, f'Expected status code was 200, ' \
        f'but {put_response.status_code} was returned. \nFull response: {put_response.text}'

    # Provoke a block from an unknown IP (default: 5 tries => ip blocked)
    api_details = get_api_details(host=host, port=port)
    api_details['base_url'] += '/security/user/authenticate'
    for i in range(max_login_attempts-1):
        get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # Request before blocking time expires. (5th try)
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)
    assert get_response.status_code == 400, f'Expected status code was 400, ' \
        f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'

    # Request after time expires.
    time.sleep(block_time) # 300 = default blocking time
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # After blocking time, status code will be 401 again (unauthorized)
    assert get_response.status_code == 401, f'Expected status code was 401, ' \
        f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'

    # DELETE configuration for security.yaml
    api_details = get_api_details()
    delete_response = requests.delete(api_details['base_url'] + '/security/config', json=data, headers=api_details['auth_headers'], verify=False)
    assert delete_response.status_code == 200, f'Expected status code was 200, ' \
        f'but {delete_response.status_code} was returned. \nFull response: {delete_response.text}'
