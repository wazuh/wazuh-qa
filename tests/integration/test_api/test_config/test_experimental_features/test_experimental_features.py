'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'experimental_features' setting of the API is working properly.
       This setting allows users to access API endpoints containing features that are under development.
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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#drop-privileges

tags:
    - api
'''
import os

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
    {'experimental_enabled'},
    {'experimental_disabled'},
])
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_experimental_features(tags_to_apply, get_configuration, configure_api_environment,
                               restart_api, wait_for_start, get_api_details):
    '''
    description: Check if requests to an experimental API endpoint are allowed according
                 to the configuration. For this purpose, it configures the API to use
                 this functionality and makes requests to it, waiting for a correct response.

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
        - Verify that when 'experimental_features' is enabled,
          it is possible to access experimental API endpoints.
        - Verify that when 'experimental_features' is disabled,
          it is not possible to access experimental API endpoints.

    input_description: Different test cases are contained in an external YAML file (conf.yaml)
                       which includes API configuration parameters.

    expected_output:
        - r'200' ('OK' HTTP status code if 'experimental_features == true')
        - r'404' ('Forbidden' HTTP status code if 'experimental_features == false')
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    experimental = get_configuration['configuration']['experimental_features']
    api_details = get_api_details()
    api_details['base_url'] += '/experimental/syscollector/os'

    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    if experimental:
        assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                                f'but {get_response.status_code} was returned. ' \
                                                f'\nFull response: {get_response.text}'
    else:
        assert get_response.status_code == 404, f'Expected status code was 404, ' \
                                                f'but {get_response.status_code} was returned. ' \
                                                f'\nFull response: {get_response.text}'
