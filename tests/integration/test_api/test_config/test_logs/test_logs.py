'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'level' setting of the API is working properly. This setting
       allows specifying the level of detail (INFO, DEBUG) of the messages written to the 'api.log' file.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh manager
       from a web browser, command line tool like 'cURL' or any script or program that can make web requests.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#logs

tags:
    - api
'''
import json
import os
import re
import pytest
import requests

import wazuh_testing as fw
from wazuh_testing import tools
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools import configuration as config
from wazuh_testing.modules.api import event_monitor as evm

# Marks

pytestmark = pytest.mark.server

# Variables

LOGS_MONITOR_TIMEOUT = 60
test_directories = [os.path.join(tools.PREFIX, 'test_logs')]
file_monitor = FileMonitor(fw.API_LOG_FILE_PATH)

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
api_configurations = config.get_api_conf(configurations_path)
cases_ids = [configuration['configuration']['logs']['level'] for configuration in api_configurations]


# Fixtures

@pytest.fixture(scope='module', params=api_configurations, ids=cases_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def test_logs(get_configuration, configure_api_environment, restart_api):
    '''
    description: Check if the logs are saved with the desired level.
                 Logs are always stored in '/var/ossec/logs/api.log', usually with level 'info'.
                 In this test the API log has 'debug' level configured.
                 It checks if logs are saved with 'debug' level.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
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
    config.check_apply_test({'logs_info', 'logs_debug'}, get_configuration['tags'])

    # Detect any "DEBUG:" message in the log path
    if get_configuration['configuration']['logs']['level'] == 'info':
        with pytest.raises(TimeoutError):
            evm.check_api_debug_log()
    else:
        evm.check_api_debug_log()


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_request_logging_request_headers(get_api_details, get_configuration, configure_api_environment, restart_api):
    '''
    description: Check if the request_logging API middleware works.

    wazuh_min_version: 4.1.0

    tier: 0

    parameters:
        - get_api_details:
            type: fixture
            brief: Get API information.
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
        - Verify that request headers are logged when using debug2 as log level.

    tags:
        - logs
        - logging
    '''
    # Perform test for all the logging levels of data/conf.yaml
    config.check_apply_test({'all'}, get_configuration['tags'])

    def callback_request_headers(line):
        match = re.match(fr".*DEBUG2: (Receiving headers.*{str(request_headers).replace('{', '').replace('}', '')}.*)",
                         line)
        if match:
            return match.group(1)

    api_details = get_api_details()

    # Make an API request
    request_headers = api_details['auth_headers']
    requests.get(f"{api_details['base_url']}/agents", headers=request_headers, verify=False)

    # Check request headers were logged in debug mode 2
    if get_configuration['configuration']['logs']['level'] != 'debug2':
        with pytest.raises(TimeoutError):
            file_monitor.start(timeout=LOGS_MONITOR_TIMEOUT, callback=callback_request_headers,
                               error_message='"DEBUG2: Receiving headers ..." event received but not '
                                             'expected.').result()
    else:
        file_monitor.start(timeout=LOGS_MONITOR_TIMEOUT, callback=callback_request_headers,
                           error_message='"DEBUG2: Receiving headers ..." event expected but not received.').result()


@pytest.mark.parametrize('method, json_body', [
    ('GET', None),
    ('POST', {"wrong_key": "value"}),
])
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_request_logging_json_body(get_api_details, get_configuration, configure_api_environment, restart_api, method,
                                   json_body):
    '''
    description: Check if the request_logging API middleware works.

    wazuh_min_version: 4.1.0

    tier: 0

    parameters:
        - get_api_details:
            type: fixture
            brief: Get API information.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_api_environment:
            type: fixture
            brief: Configure a custom environment for API testing.
        - restart_api:
            type: fixture
            brief: Reset 'api.log' and start a new monitor.
        - method:
            type: str
            brief: Method used in the /agents API request.
        - json_body:
            type: dict
            brief: JSON body used in the /agents API request.

    assertions:
        - Verify that if the request has a JSON body, it is logged.
        - Verify that if the request does not have a JSON body, the default body ({}) is logged.

    tags:
        - logs
        - logging
    '''
    # Perform test for all the logging levels of data/conf.yaml
    config.check_apply_test({'all'}, get_configuration['tags'])

    def callback_body_logged(line):
        match = re.match(fr'.*INFO: (.*"{method} /agents" with parameters .* and body '
                         fr'{json.dumps(json_body) if json_body else {} }.*)', line)
        if match:
            return match.group(1)

    api_details = get_api_details()

    # Make an API request
    getattr(requests, method.lower())(f"{api_details['base_url']}/agents", headers=api_details['auth_headers'],
                                      verify=False, json=json_body)

    # Check the expected body was logged
    file_monitor.start(timeout=LOGS_MONITOR_TIMEOUT, callback=callback_body_logged,
                       error_message=f'API request informative log for endpoint "{method} /agents" with body: '
                                     f'{json.dumps(json_body) if json_body else {} } expected but not '
                                     f'received').result()
