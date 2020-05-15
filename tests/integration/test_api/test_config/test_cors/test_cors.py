# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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
def test_cors(origin, tags_to_apply, get_configuration, configure_api_environment,
              restart_api, wait_for_start, get_api_details):
    """Check if expected headers are returned when CORS is enabled.

    When CORS is enabled, special headers must be returned in case the
    request origin matches the one established in the CORS configuration
    of the API.

    Parameters
    ----------
    origin : str
        Origin path to be appended as a header in the request.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
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
