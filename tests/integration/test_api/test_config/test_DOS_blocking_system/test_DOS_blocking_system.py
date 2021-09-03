'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

description:
    These tests will check if the DOS attacks blocking feature
    of the API handled by the `apid` daemon is working properly.

tiers:
    - 0

component:
    manager

path:
    tests/integration/test_api/test_config/test_DOS_blocking_system/

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
import time

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
    {'config1'},
    {'config2'}
])
def test_DOS_blocking_system(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                             wait_for_start, get_api_details):
    '''
    description:
        Verify that the blocking system for IPs detected as DOS attack works.
        For this purpose, the test causes an IP blocking, make a request
        within the same minute, make a request after the minute.

    wazuh_min_version:
        4.1

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
        - Verify that the IP is blocked using multiple request.
        - Check if the IP is still blocked within the one-minute block time.
        - Verify that the IP is not blocked when expires the block time.

    test_input:
        Different test cases are contained in an external `YAML` file (conf.yaml)
        which includes API configuration parameters.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:
        - dos_attack
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    max_request_per_minute = get_configuration['configuration']['access']['max_request_per_minute']
    api_details = get_api_details()

    # Provoke an api block (default: 300 requests)
    api_details['base_url'] += '/agents'
    for _ in range(max_request_per_minute):
        requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # Request within the same minute
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)
    assert get_response.status_code == 429, f'Expected status code was 429, ' \
                                            f'but {get_response.status_code} was returned. ' \
                                            f'\nFull response: {get_response.text}'

    # Request after the minute.
    time.sleep(60)  # 60 = 1 minute
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # After blocking time, status code will be 200 again
    assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                            f'but {get_response.status_code} was returned. ' \
                                            f'\nFull response: {get_response.text}'
