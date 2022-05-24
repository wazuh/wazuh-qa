'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: There is an API configuration option, called logs, which allows to log in 4 different ways ("json", "plain",
       "json,plain", and "plain,json") through the format field. When the API is configured with one of those values the
       logs are stored in the api.log and api.json files.
tier: 2
modules:
    - api
components:
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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#logs
tags:
    - api
    - logs
    - logging
'''
import os
import time

import pytest
import requests
from wazuh_testing.api import API_HOST, API_LOGIN_ENDPOINT, API_PASS, API_PORT, API_PROTOCOL, API_USER, \
                              get_login_headers
from wazuh_testing.modules import api
from wazuh_testing.modules.api import event_monitor as evm
from wazuh_testing.tools import API_JSON_LOG_FILE_PATH, PREFIX, API_DAEMON, MODULES_DAEMON, ANALYSISD_DAEMON, \
                                EXEC_DAEMON, DB_DAEMON, REMOTE_DAEMON
from wazuh_testing.tools.configuration import get_api_conf

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2), pytest.mark.server]

# Variables
daemons_handler_configuration = {
    'daemons': [API_DAEMON, MODULES_DAEMON, ANALYSISD_DAEMON, EXEC_DAEMON, DB_DAEMON, REMOTE_DAEMON]
}
test_directories = [os.path.join(PREFIX, 'test_logs')]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'configuration_api_logs_format.yaml')
configurations = get_api_conf(configurations_path)
tcase_ids = [f"level_{configuration['configuration']['logs']['level']}"
             f"_format_{configuration['configuration']['logs']['format'].replace(',','_')}"
             for configuration in configurations]


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=tcase_ids)
def get_configuration(request):
    """Get configurations from the module."""

    return request.param


@pytest.fixture(scope='function')
def send_request(remaining_attempts=3):
    """Send a login request to the API.

    Args:
        remaining_attempts (int): number of request attemps
    """
    login_url = f"{API_PROTOCOL}://{API_HOST}:{API_PORT}{API_LOGIN_ENDPOINT}"
    # Initialize variables to avoid the UnboundLocalError
    result = None
    response = None

    # Make 3 attempts to wait for the API to start correctly
    while remaining_attempts > 0:
        try:
            response = requests.get(login_url, headers=get_login_headers(API_USER, API_PASS), verify=False,
                                    timeout=api.T_5)
        except requests.exceptions.ConnectionError:
            # Capture the exception and wait
            time.sleep(api.T_10)
            # Decrease the number of remaining attempts
            remaining_attempts -= 1
        else:
            result = response.status_code
            break

    yield result


# Tests
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_api_logs_formats(get_configuration, configure_api_environment, clean_log_files, daemons_handler,
                          wait_for_start, send_request):
    '''
    description: Check if the logs of the API are stored in the specified formats and the content of the log
                 files are the expected.
    wazuh_min_version: 4.4.0
    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_api_environment:
            type: fixture
            brief: Configure a custom environment for API testing.
        - clean_log_files:
            type: fixture
            brief: Reset the log files of the API and delete the rotated log files.
        - daemons_handler:
            type: fixture
            brief: Handle the Wazuh daemons.
        - wait_for_start:
            type: fixture
            brief: Wait until the API starts.
        - send_request:
            type: fixture:
            brief: Send a login request to the API.
    assertions:
        - Verify that the expected log exists in the log file.
        - Verify that the values of the log are the same in both log formats.
    input_description: The test gets the configuration from the YAML file, which contains the API configuration.
    expected_output:
        - The log was not expected.
        - The length of the subgroups of the match is not equal.
        - The values of the logs don't match.
    tags:
        - api
        - logs
        - logging
    '''
    current_formats = get_configuration['configuration']['logs']['format'].split(',')
    current_level = get_configuration['configuration']['logs']['level']
    response_status_code = send_request

    if current_level == 'error':
        assert response_status_code == 500, f"The status code was {response_status_code}. \nExpected: 500."
    else:
        assert response_status_code == 200, f"The status code was {response_status_code}. \nExpected: 200."

    if 'json' in current_formats:
        if current_level == 'error':
            evm.check_api_timeout_error(file_to_monitor=API_JSON_LOG_FILE_PATH)
        else:
            evm.check_api_login_request(file_to_monitor=API_JSON_LOG_FILE_PATH)
    if 'plain' in current_formats:
        if current_level == 'error':
            evm.check_api_timeout_error()
        else:
            evm.check_api_login_request()
