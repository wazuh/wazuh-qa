'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

description:
    These tests will check if the IP blocking feature of the API handled by the `apid` daemon is working properly.

tiers:
    - 0

component:
    manager

path:
    tests/integration/test_api/test_config/test_bruteforce_blocking_system/

daemons:
    - apid
    - analysisd
    - syscheckd
    - wazuh-db

os_support:
    - linux, rhel5
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
def test_bruteforce_blocking_system(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                                    wait_for_start, get_api_details):
    '''
    description:
        Check that the blocking time for IPs detected as brute-force attack works.
        For this purpose, the test causes an IP blocking, make a request before
        the blocking time finishes and one after the blocking time.

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
        - Check if the IP is blocked using incorrect credentials.
        - Check that the IP is still blocked even when using the correct credentials within the block time.

    test_input:
        Different test cases are contained in an external `YAML` file (conf.yaml)
        which includes API configuration parameters.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:
        - brute_force_attack
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    block_time = get_configuration['configuration']['access']['block_time']
    max_login_attempts = get_configuration['configuration']['access']['max_login_attempts']

    # Provoke a block from an unknown IP ('max_login_attempts' attempts with incorrect credentials).
    with pytest.raises(RuntimeError):
        get_api_details(user='wrong', password='wrong', login_attempts=max_login_attempts, sleep_time=0)

    # Request with correct credentials before blocking time expires.
    with pytest.raises(RuntimeError) as login_exc:
        get_api_details()
    assert 'Error obtaining login token' in login_exc.value.args[0], f'An error getting the token was expected, but ' \
                                                                     f'it was not obtained. \nFull response: ' \
                                                                     f'{login_exc.value}'

    # Request after time expires.
    time.sleep(block_time)  # 300 = default blocking time
