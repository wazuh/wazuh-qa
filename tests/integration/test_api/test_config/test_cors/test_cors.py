'''
brief:
    These tests will check if the CORS (Cross-origin resource sharing) feature
    of the API handled by the `apid` daemon is working properly.
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
modules:
    - api
daemons:
    - wazuh-apid
    - wazuh-analysisd
    - wazuh-syscheckd
    - wazuh-wazuh-db
category:
    integration
os_platform:
    - linux
os_vendor:
    - redhat
    - debian
    - ubuntu
    - alas
    - arch-linux
    - centos
os_version:
    - centos6
    - centos7
    - centos8
    - rhel6
    - rhel7
    - rhel8
    - buster
    - stretch
    - wheezy
    - bionic
    - xenial
    - trusty
    - amazon-linux-1
    - amazon-linux-2
tiers:
    - 0
tags:
    - api
component:
    - manager
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

@pytest.mark.xfail(reason="Error fixed in this issue: https://github.com/wazuh/wazuh/issues/8485")
@pytest.mark.parametrize('origin, tags_to_apply', [
    ('https://test_url.com', {'cors'}),
    ('http://other_url.com', {'cors'}),
])
def test_cors(origin, tags_to_apply, get_configuration, configure_api_environment,
              restart_api, wait_for_start, get_api_details):
    '''
    description:
        Check if expected headers are returned when CORS is enabled.
        When CORS is enabled, special headers must be returned in case the
        request origin matches the one established in the CORS configuration
        of the API.
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
    wazuh_min_version:
        3.13
    behaviour:
        - Perform different requests with CORS enabled and disabled, then check the responses for matching headers.
    expected_behaviour:
        - The `Access-Control-Allow-Origin` header is received when CORS is enabled.
        - The `Access-Control-Expose-Headers` header is received when CORS is enabled.
        - The `Access-Control-Allow-Credentials` header is received when CORS is enabled.
        - the `Access-Control-Allow-Origin` header is not received when CORS is disabled.
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
