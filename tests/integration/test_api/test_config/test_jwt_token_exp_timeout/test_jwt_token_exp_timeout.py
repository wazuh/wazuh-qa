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
configurations_path = os.path.join(test_data_path, 'conf_exp_timeout.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'short_exp_time'},
    {'long_exp_time'}
])
def test_jwt_token_exp_timeout(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                               wait_for_start, get_api_details):
    """Verify that the JWT token expires after defined time.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    short_exp = get_configuration['tags'][0] == 'short_exp_time'
    api_details = get_api_details()
    api_details['base_url'] += '/manager/info'

    # Request manager info before token expires.
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)
    assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                            f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'

    # Request manager info after token expires.
    time.sleep(min(get_configuration['security_config']['auth_token_exp_timeout'] + 2, 10))
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # If token has expired, user can't access that information.
    if short_exp:
        assert get_response.status_code == 401, f'Expected status code was 401, ' \
                                                f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'
    else:
        assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                                f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'
