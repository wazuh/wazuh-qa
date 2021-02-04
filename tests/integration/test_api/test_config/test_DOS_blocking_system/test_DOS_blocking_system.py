# Copyright (C) 2015-2021, Wazuh Inc.
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
def test_DOS_blocking_system(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                             wait_for_start, get_api_details):
    """Check the correct functionality of the DOS blocking system.

    Provoke a block, make a request within the same minute, make a request after the minute.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    max_request_per_minute = get_configuration['configuration']['access']['max_request_per_minute']
    api_details = get_api_details()

    # Provoke an api block (default: 300 requests)
    api_details['base_url'] += '/agents'
    for _ in range(max_request_per_minute):
        requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # Request within the same minute
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)
    assert get_response.status_code == 429, f'Expected status code was 429, ' \
                                            f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'

    # Request after the minute.
    time.sleep(60)  # 60 = 1 minute
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # After blocking time, status code will be 200 again
    assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                            f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'
