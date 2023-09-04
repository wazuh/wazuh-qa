'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: There is an API configuration option, called logs, which allows to log in 4 different ways ("json", "plain",
       "json,plain", and "plain,json") through the format field. When the API is configured with one of those values the
       logs are stored in the api.log and api.json files.

components:
    - api

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-execd
    - wazuh-db
    - wazuh-remoted

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

import wazuh_testing as fw
from wazuh_testing import api
from wazuh_testing.tools import configuration as config
from wazuh_testing.modules.api import event_monitor as evm

# Marks
pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and test cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_api_logs_format.yaml')
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_api_logs_formats.yaml')

# API log formats configurations
configuration_parameters, configuration_metadata, case_ids = config.get_test_cases_data(test_cases_path)
configurations = config.load_configuration_template(configurations_path, configuration_parameters,
                                                    configuration_metadata)


@pytest.fixture(scope='function')
def send_request(remaining_attempts=3):
    """Send a login request to the API.

    Args:
        remaining_attempts (int): number of request attemps
    """
    login_url = f"{api.API_PROTOCOL}://{api.API_HOST}:{api.API_PORT}{api.API_LOGIN_ENDPOINT}"
    # Initialize variables to avoid the UnboundLocalError
    result = None
    response = None

    # Make 3 attempts to wait for the API to start correctly
    while remaining_attempts > 0:
        try:
            response = requests.post(login_url, headers=api.get_login_headers(api.API_USER, api.API_PASS), verify=False,
                                     timeout=fw.T_5)
        except requests.exceptions.ConnectionError:
            # Capture the exception and wait
            time.sleep(fw.T_10)
            # Decrease the number of remaining attempts
            remaining_attempts -= 1
        else:
            result = response.status_code
            break

    yield result


# Tests

@pytest.mark.tier(level=1)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_api_logs_formats(configuration, metadata, set_api_configuration, clean_log_files, restart_api_function,
                          wait_for_start_function, send_request):
    '''
    description: Check if the logs of the API are stored in the specified formats and the content of the log
                 files are the expected.

    tier: 1

    test_phases:
        - Set a custom API configuration, with custom intervals and logs.
        - Restart the API daemon and the daemons related to it.
        - Send a request to the API to generate the desired event.
        - Check in the log file that the expected event has been recorded.

    wazuh_min_version: 4.4.0

    parameters:
        - configuration:
            type: dict
            brief: API configuration data. Needed for set_api_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - set_api_configuration:
            type: fixture
            brief: Set API custom configuration.
        - clean_log_files:
            type: fixture
            brief: Reset the log files of the API and delete the rotated log files.
        - restart_api_function:
            type: fixture
            brief: Restart all deamons related to the API before the test and stop them after it finished.
        - wait_for_start_function:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.
        - send_request:
            type: fixture
            brief: Send a login request to the API.

    assertions:
        - Verify that the response status code is the expected one.
        - Verify that the expected log exists in the log file.

    input_description: The test gets the configuration from the YAML file, which contains the API configuration.

    expected_output:
        - r".*ERROR.*{api.TIMEOUT_ERROR_LOG}.*" (Timeout error log)
        - r".*INFO.*{user}.*{host}.*{API_LOGIN_ENDPOINT}.*" (Authentication log)

    tags:
        - api
        - logs
        - logging
    '''
    current_formats = metadata['log_format'].split(',')
    current_level = metadata['log_level']
    response_status_code = send_request

    # Check if the status code of the response is the expected depending on the configured level
    if current_level == 'error':
        assert response_status_code == 500, f"The status code was {response_status_code}. \nExpected: 500."
    else:
        assert response_status_code == 200, f"The status code was {response_status_code}. \nExpected: 200."

    # Check whether the expected event exists in the log files according to the configured levels
    if 'json' in current_formats:
        if current_level == 'error':
            evm.check_api_timeout_error(file_to_monitor=fw.API_JSON_LOG_FILE_PATH)
        else:
            evm.check_api_login_request(file_to_monitor=fw.API_JSON_LOG_FILE_PATH)
    if 'plain' in current_formats:
        if current_level == 'error':
            evm.check_api_timeout_error()
        else:
            evm.check_api_login_request()
