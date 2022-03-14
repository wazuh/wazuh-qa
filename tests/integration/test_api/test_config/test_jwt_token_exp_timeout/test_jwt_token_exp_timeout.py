'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'auth_token_exp_timeout' setting of the API is working properly.
       This setting allows specifying the expiration time of the 'JWT' token used for authentication.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh manager
       from a web browser, command line tool like 'cURL' or any script or program that can make web requests.

components:
    - api

suite: config

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-analysisd
    - wazuh-syscheckd
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#auth-token-exp-timeout
    - https://en.wikipedia.org/wiki/JSON_Web_Token

tags:
    - api
'''
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
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_jwt_token_exp_timeout(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                               wait_for_start, get_api_details):
    '''
    description: Check if the API 'JWT' token expires after defined time. For this purpose,
                 an expiration time is set for the token, and API requests are made before
                 and after the expiration time, waiting for a valid 'HTTP status code'.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_api_environment:
            type: fixture
            brief: Configure a custom environment for API testing.
        - restart_api:
            type: fixture
            brief: Reset 'api.log' and start a new monitor.
        - wait_for_start:
            type: fixture
            brief: Wait until the API starts.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the API requests are successful if the 'JWT' token has not expired and vice versa.

    input_description: Different test cases are contained in an external YAML file (conf_exp_timeout.yaml)
                       which includes API configuration parameters (timeouts for token expiration).

    expected_output:
        - r'200' ('OK' HTTP status code if the token has not expired)
        - r'401' ('Unauthorized' HTTP status code if the token has expired)

    tags:
        - token
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    short_exp = get_configuration['tags'][0] == 'short_exp_time'
    api_details = get_api_details()
    api_details['base_url'] += '/manager/info'

    # Request manager info before token expires.
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)
    assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                            f'but {get_response.status_code} was returned. ' \
                                            f'\nFull response: {get_response.text}'

    # Request manager info after token expires.
    time.sleep(min(get_configuration['security_config']['auth_token_exp_timeout'] + 2, 10))
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # If token has expired, user can't access that information.
    if short_exp:
        assert get_response.status_code == 401, f'Expected status code was 401, ' \
                                                f'but {get_response.status_code} was returned. ' \
                                                f'\nFull response: {get_response.text}'
    else:
        assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                                f'but {get_response.status_code} was returned. ' \
                                                f'\nFull response: {get_response.text}'
