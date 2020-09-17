# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

import pytest
import requests

from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.services import control_service

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
def test_bruteforce_blocking_system(tags_to_apply, get_configuration, configure_api_environment, restart_api,
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
    block_time = get_configuration['conf']['block_time']
    max_login_attempts = get_configuration['conf']['max_login_attempts']

    # PUT configuration for api.yaml
    api_details = get_api_details()
    data = {
        'access': {'block_time': block_time, 'max_login_attempts': max_login_attempts, 'max_request_per_minute': 300}}
    put_response = requests.put(api_details['base_url'] + '/manager/api/config', json=data,
                                headers=api_details['auth_headers'], verify=False)
    assert put_response.status_code == 200, f'Expected status code was 200, ' \
                                            f'but {put_response.status_code} was returned. \nFull response: {put_response.text}'

    control_service('restart')

    # Provoke a block from an unknown IP ('max_login_attempts' attempts with incorrect credentials).
    for _ in range(max_login_attempts):
        with pytest.raises(Exception):
            get_api_details(user='wrong', password='wrong')

    # Request with correct credentials before blocking time expires.
    with pytest.raises(Exception) as login_exc:
        get_api_details()
    assert 'Error obtaining login token' in login_exc.value.args[0], f'An error getting the token was expected, but ' \
                                                                     f'it was not obtained. \nFull response: ' \
                                                                     f'{login_exc.value}'

    # Request after time expires.
    time.sleep(block_time)  # 300 = default blocking time

    try:
        api_details = get_api_details()
    except Exception as e:
        pytest.fail("No exception was expected when obtaining login token after 'block_time' has expired, but"
                    f"this was returned: {e}")

    # DELETE configuration for api.yaml
    delete_response = requests.delete(api_details['base_url'] + '/manager/api/config', json=data,
                                      headers=api_details['auth_headers'], verify=False)
    assert delete_response.status_code == 200, f'Expected status code was 200, ' \
                                               f'but {delete_response.status_code} was returned. \nFull response: {delete_response.text}'
