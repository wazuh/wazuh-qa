'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief:
    These tests will check if the 'CORS' (Cross-origin resource sharing) feature of the API handled
    by the 'wazuh-apid' daemon is working properly. The Wazuh API is an open source 'RESTful' API
    that allows for interaction with the Wazuh manager from a web browser, command line tool
    like 'cURL' or any script or program that can make web requests.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#cors
    - https://en.wikipedia.org/wiki/Cross-origin_resource_sharing

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

@pytest.mark.parametrize('origin, tags_to_apply', [
    ('https://test_url.com', {'cors'}),
    ('http://other_url.com', {'cors'}),
])
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_cors(origin, tags_to_apply, get_configuration, configure_api_environment,
              restart_api, wait_for_start, get_api_details):
    '''
    description: Check if expected headers are returned when 'CORS' is enabled.
                 When 'CORS' is enabled, special headers must be returned in case the
                 request origin matches the one established in the 'CORS' configuration
                 of the API.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - origin:
            type: set
            brief: Origin path to be appended as a header in the request.
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
        - Verify that when CORS is enabled, the 'Access-Control-Allow-Origin' header is received.
        - Verify that when CORS is enabled, the 'Access-Control-Expose-Headers' header is received.
        - Verify that when CORS is enabled, the 'Access-Control-Allow-Credentials' header is received.
        - Verify that when CORS is disabled, the 'Access-Control-Allow-Origin' header is not received.

    input_description: A test case is contained in an external YAML file (conf.yaml)
                       which includes API configuration parameters.

    expected_output:
        - r'Access-Control-Allow-Origin'
        - r'Access-Control-Expose-Headers'
        - r'https://test_url.com'
        - r'true'

    tags:
        - cors
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    api_details = get_api_details()
    api_details['auth_headers']['origin'] = origin

    # Expected content from the response headers.
    source_route = get_configuration['configuration']['cors']['source_route']
    expose_headers = get_configuration['configuration']['cors']['expose_headers']
    allow_headers = get_configuration['configuration']['cors']['allow_headers']
    allow_credentials = str(get_configuration['configuration']['cors']['allow_credentials']).lower()

    # Request to default API url.
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # If origin is allowed, check CORS headers.
    if origin == source_route:
        assert 'Access-Control-Allow-Origin' in get_response.headers.keys(), 'Allow origin not found in headers'
        assert get_response.headers['Access-Control-Allow-Origin'] == origin, 'Expected header not returned.'
        assert all(header in get_response.headers['Access-Control-Expose-Headers'] for header in expose_headers), \
            'Expected header not returned.'
        assert get_response.headers['Access-Control-Allow-Credentials'] == allow_credentials, 'Expected header not ' \
                                                                                              'returned.'
        try:
            assert all(header in get_response.headers['Access-Control-Allow-Headers'] for header in allow_headers)
        except KeyError:
            pytest.xfail(reason='Xfailed due to Access-Control-Allow-Headers not being returned.')
    else:
        assert 'Access-Control-Allow-Origin' not in get_response.headers.keys(), 'Allow origin found in headers'
