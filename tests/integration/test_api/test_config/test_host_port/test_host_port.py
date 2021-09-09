'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

brief:
    These tests will check that the settings related to the API
    host address and listening port are working correctly.

tier:
    0

modules:
    - api

components:
    - manager

path:
    tests/integration/test_api/test_config/test_host_port/test_host_port.py

daemons:
    - wazuh-apid
    - wazuh-analysisd
    - wazuh-syscheckd
    - wazuh-db

os_platform:
    - linux

os_version:
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#api-configuration-options

tags:
    - api
'''
import os

import pytest
import requests
from wazuh_testing import global_parameters
from wazuh_testing.api import callback_detect_api_start
from wazuh_testing.tools import API_LOG_FILE_PATH
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.server

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(API_LOG_FILE_PATH)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('expected_exception, tags_to_apply', [
    (False, {'conf_1'}),
    (True, {'conf_2'}),
])
def test_host_port(expected_exception, tags_to_apply,
                   get_configuration, configure_api_environment, restart_api, get_api_details):
    '''
    description:
        Try different host and port configurations. For this purpose, apply multiple
        combinations of host and port, verify that the `aiohttp` http framework correctly
        publishes that value in the `api.log` and check that the request returns the expected one.

    wazuh_min_version:
        4.2

    parameters:
        -  expected_exception:
            type: bool
            brief: True if an exception must be raised, false otherwise.
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
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the API starts listening on the specified IP address and port.
        - Verify that using a valid configuration, the API requests are performed correctly.
        - Verify that no unexpected exceptions occur.

    input_description:
        Different test cases are contained in an external `YAML` file (conf.yaml)
        which includes API configuration parameters (IP addresses and ports).

    expected_output:
        - r'.*INFO: Listening on (.+)..'
        - r'{host}{port}' (`host` and `port` are obtained from each test_case.)
        - r'200' ('OK' HTTP status code)
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    host = get_configuration['configuration']['host']
    port = get_configuration['configuration']['port']

    # Check that expected host and port are shown in api.log
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 10,
                                    callback=callback_detect_api_start,
                                    error_message='Did not receive expected "Listening on ..." event').result()
    assert event == f"{host}:{port}", f'Expected API log was "{host}:{port}", but the returned one is "{event}".'

    # Perform actual request and verify if response code is the expected one.
    try:
        api_details = get_api_details(host=host, port=port, timeout=5)
        r = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

        assert not expected_exception, 'Exception was expected but not received.'
        assert r.status_code == 200, f'Expected status code was 200, but {r.status_code} was received.'
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):
        assert expected_exception, 'Request got unexpected exception.'
