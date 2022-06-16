'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check that the settings related to the API host address and listening port
       are working correctly. The Wazuh API is an open source 'RESTful' API that allows for interaction
       with the Wazuh manager from a web browser, command line tool like 'cURL' or any script
       or program that can make web requests.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#api-configuration-options

tags:
    - api
'''
import os

import pytest
import requests
from wazuh_testing.modules.api import event_monitor as evm
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
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_host_port(expected_exception, tags_to_apply,
                   get_configuration, configure_api_environment, restart_api, get_api_details):
    '''
    description: Check different host and port configurations. For this purpose, apply multiple
                 combinations of host and port, verify that the 'aiohttp' http framework correctly
                 publishes that value in the 'api.log' and check that the request returns the expected one.

    wazuh_min_version: 4.2.0

    tier: 0

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
            brief: Reset 'api.log' and start a new monitor.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the API starts listening on the specified IP address and port.
        - Verify that using a valid configuration, the API requests are performed correctly.
        - Verify that no unexpected exceptions occur.

    input_description: Different test cases are contained in an external YAML file (conf.yaml)
                       which includes API configuration parameters (IP addresses and ports).

    expected_output:
        - r'.*INFO: Listening on (.+)..'
        - r'{host}{port}' ('host' and 'port' are obtained from each test_case.)
        - r'200' ('OK' HTTP status code)
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    host = get_configuration['configuration']['host']
    port = get_configuration['configuration']['port']

    # Check that expected host and port are shown in api.log
    evm.check_api_start_log(file_to_monitor=API_LOG_FILE_PATH, host=host, port=port)

    # Perform actual request and verify if response code is the expected one.
    try:
        api_details = get_api_details(host=host, port=port, timeout=5)
        r = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

        assert not expected_exception, 'Exception was expected but not received.'
        assert r.status_code == 200, f'Expected status code was 200, but {r.status_code} was received.'
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):
        assert expected_exception, 'Request got unexpected exception.'
