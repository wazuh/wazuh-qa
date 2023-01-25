'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the set_secure_headers middleware of the API handled by the 'wazuh-apid' daemon is
       working properly. The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh
       manager from a web browser, command line tool like 'cURL' or any script or program that can make web requests.

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
    - headers
'''
import pytest
import requests

# Marks
pytestmark = [pytest.mark.server]


# Tests

@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_secure_headers(restart_api_module, get_api_details):
    '''
    description: Check if the set_secure_headers API middleware works.
                 For this purpose, the test makes an API request and checks that the response headers fulfill the REST
                 recommended standard.

    wazuh_min_version: 4.1.0

    tier: 0

    parameters:
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the response headers fulfill the REST recommended standard in terms of security.

    tags:
        - headers
        - security
    '''
    api_details = get_api_details()

    # Make an API request
    response = requests.get(f"{api_details['base_url']}/agents", headers=api_details['auth_headers'], verify=False)

    # Check response headers fulfill the REST standard
    security_headers_keys = {'Cache-control', 'Content-Security-Policy', 'Content-Type', 'Strict-Transport-Security',
                             'X-Content-Type-Options', 'X-Frame-Options'}
    security_headers_keys_with_values = {'Cache-control': 'no-store', 'Content-Security-Policy': 'none',
                                         'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY'}

    # Check that all the security headers are in the response
    assert security_headers_keys.issubset(response.headers.keys())
    # Check that Cache-control, Content-Security-Policy, X-Content-Type-Options and X-Frame-Options have the expected
    # values
    assert all(
        security_headers_keys_with_values[key] in response.headers[key] for key in security_headers_keys_with_values)
