'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the response_postprocessing middleware of the API handled by the 'wazuh-apid' daemon is
       working properly. The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh
       manager from a web browser, command line tools like 'cURL' or any script or program that can make web requests.

components:
    - api

suite: middlewares

targets:
    - manager

daemons:
    - wazuh-apid

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html

tags:
    - api
    - response
    - response fields
'''
import json

import pytest
import requests
from wazuh_testing import api

# Marks
pytestmark = [pytest.mark.server]


# Tests

@pytest.mark.parametrize(
    'method, endpoint_url, json_body, use_login_token, expected_status_code, expected_response_text', [
        ('POST', '/agents', {"wrong_key": "val"}, True, 400,
         {'title': 'Bad Request', 'detail': "'name' is a required property"}),
        ('GET', '/not_found_endpoint', None, True, 404,
         {'title': 'Not Found', 'detail': '404: Not Found'}),
        ('GET', '/agents', None, False, 401,
         {'title': 'Unauthorized', 'detail': 'No authorization token provided'}),
        ('POST', '/security/user/authenticate', None, False, 401,
         {'title': 'Unauthorized', 'detail': 'Invalid credentials'})
    ])
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_response_postprocessing(restart_api_module, get_api_details, method, endpoint_url, json_body, use_login_token,
                                 expected_status_code, expected_response_text):
    '''
    description: Check if the response_postprocessing API middleware works.

    wazuh_min_version: 4.0.0

    tier: 0

    parameters:
        - get_api_details:
            type: fixture
            brief: Get API information.
        - method:
            type: str
            brief: Method used in the API request.
        - endpoint_url:
            type: str
            brief: Endpoint requested in the test.
        - json_body:
            type: dict
            brief: JSON body used in POST API requests.
        - use_login_token:
            type: bool
            brief: Variable used to determine whether a login token for the API request is needed or not.
        - expected_status_code:
            type: int
            brief: Status code expected in the API response.
        - expected_response_text:
            type: dict
            brief: Dictionary representing the expected API response text.

    assertions:
        - Verify that the fields are the expected ones when getting a 400 status code response (bad request).
        - Verify that the fields are the expected ones when getting a 404 status code response (not found).
        - Verify that the details are the expected ones when getting a 401 status code response (unauthorized).
        - Verify that the details are the expected ones when getting a 401 status code response (invalid credentials).

    tags:
        - headers
        - security
    '''
    api_details = get_api_details()
    headers = api_details['auth_headers'] if use_login_token else api.get_login_headers('wrong_user', 'wrong_password')

    # Make an API request
    response = getattr(requests, method.lower())(f"{api_details['base_url']}{endpoint_url}", headers=headers,
                                                 verify=False, json=json_body)

    assert response.headers['Content-Type'] == 'application/problem+json; charset=utf-8'
    assert response.status_code == expected_status_code
    assert json.loads(response.text) == expected_response_text  # type and status keys deleted
