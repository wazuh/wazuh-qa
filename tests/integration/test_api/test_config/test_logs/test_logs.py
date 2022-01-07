'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'level' setting of the API is working properly. This setting
       allows specifying the level of detail (INFO, DEBUG) of the messages written to the 'api.log' file.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh manager
       from a web browser, command line tool like 'cURL' or any script or program that can make web requests.

tier: 0

modules:
    - api

components:
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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#logs

tags:
    - api
'''
import os

import pytest
from wazuh_testing.api import callback_detect_api_debug
from wazuh_testing.tools import PREFIX, API_LOG_FILE_PATH
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.server

# Variables

test_directories = [os.path.join(PREFIX, 'test_logs')]
file_monitor = FileMonitor(API_LOG_FILE_PATH)

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
    {'logs_info'},
    {'logs_debug'}
])
def test_logs(tags_to_apply, get_configuration, configure_api_environment, restart_api):
    '''
    description: Check if the logs are saved with the desired level.
                 Logs are always stored in '/var/ossec/logs/api.log', usually with level 'info'.
                 In this test the API log has 'debug' level configured.
                 It checks if logs are saved with 'debug' level.

    wazuh_min_version: 4.2.0

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
            brief: Reset 'api.log' and start a new monitor.

    assertions:
        - Verify that no 'DEBUG' messages are written when the value of the 'level' setting is set to 'info'.
        - Verify that 'DEBUG' messages are written when the value of the 'level' setting is set to 'debug'.

    input_description: Different test cases are contained in an external YAML file (conf.yaml)
                       which includes API configuration parameters (log levels).

    expected_output:
        - r'.*DEBUG: (.*)'

    tags:
        - logs
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Detect any "DEBUG:" message in the log path
    if get_configuration['configuration']['logs']['level'] == 'info':
        with pytest.raises(TimeoutError):
            file_monitor.start(timeout=15, callback=callback_detect_api_debug,
                               error_message='"DEBUG: ..." event received but not expected.').result()
    else:
        file_monitor.start(timeout=60, callback=callback_detect_api_debug,
                           error_message='Did not receive expected "DEBUG: ..." event')
