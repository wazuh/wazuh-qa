# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from json import loads

import pytest
import requests

from wazuh_testing.api import API_PROTOCOL, API_HOST, API_PORT, API_LOGIN_ENDPOINT, \
    API_USER, API_PASS, get_login_headers
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
])
def test_request_timeout(tags_to_apply, get_configuration, configure_api_environment, restart_api,
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
    get_response = requests.get(f'{API_PROTOCOL}://{API_HOST}:{API_PORT}{API_LOGIN_ENDPOINT}',
                                headers=get_login_headers(API_USER, API_PASS), verify=False)

    assert get_response.status_code == 500, f'Expected status code was 500, ' \
                                            f'but {get_response.status_code} was returned. \n' \
                                            f'Full response: {get_response.text}'
    assert loads(get_response.text)['error'] == 3021  # Timeout error
