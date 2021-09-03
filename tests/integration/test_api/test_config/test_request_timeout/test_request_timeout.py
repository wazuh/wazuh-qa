'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

description:
    These tests will check if the `request_timeout` setting of the API is working properly.
    This setting allows specifying the time limit for the API to process a request.

tiers:
    - 0

component:
    manager

path:
    tests/integration/test_api/test_config/test_request_timeout/

daemons:
    - apid
    - analysisd
    - syscheckd
    - wazuh-db

os_support:
    - linux, centos 6
    - linux, centos 7
    - linux, centos 8
    - linux, rhel6
    - linux, rhel7
    - linux, rhel8
    - linux, amazon linux 1
    - linux, amazon linux 2
    - linux, debian buster
    - linux, debian stretch
    - linux, debian wheezy
    - linux, ubuntu bionic
    - linux, ubuntu xenial
    - linux, ubuntu trusty
    - linux, arch linux

coverage:

pytest_args:

tags:
    - api
'''
import os
from json import loads

import pytest
import requests

import wazuh_testing.api as api
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
    '''
    description:
        Check that the maximum request time for an API request works.
        For this purpose, a value of `0` seconds is set for the `request_timeout`
        setting, and a request is made to the API, expecting an error in the response.

    wazuh_min_version:
        4.3

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
            brief: Reset `api.log` and start a new monitor.

        - wait_for_start:
            type: fixture
            brief: Wait until the API starts.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that `status code` 500 (internal server error) is received when the request is made.
        - Verify that the API error `3021` (timeout error) is in the response.

    test_input:
        A test case is contained in an external `YAML` file (conf.yaml)
        which includes API configuration parameters.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:

    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    get_response = requests.get(f'{api.API_PROTOCOL}://{api.API_HOST}:{api.API_PORT}{api.API_LOGIN_ENDPOINT}',
                                headers=api.get_login_headers(api.API_USER, api.API_PASS), verify=False)

    assert get_response.status_code == 500, f'Expected status code was 500, ' \
                                            f'but {get_response.status_code} was returned. \n' \
                                            f'Full response: {get_response.text}'
    assert loads(get_response.text)['error'] == 3021  # Timeout error
