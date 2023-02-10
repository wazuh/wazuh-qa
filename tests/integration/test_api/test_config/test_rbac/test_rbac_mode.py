'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'rbac_mode' (Role-Based Access Control) setting of the API
       is working properly. This setting allows you to specify the operating mode between
       'whitelist mode' and 'blacklist mode'. The Wazuh API is an open source 'RESTful' API
       that allows for interaction with the Wazuh manager from a web browser, command line tool
       like 'cURL' or any script or program that can make web requests.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#rbac-mode
    - https://en.wikipedia.org/wiki/Role-based_access_control

tags:
    - api
'''
import os
import sqlite3

import pytest
import requests
from wazuh_testing.fim import WAZUH_PATH
from wazuh_testing.tools.configuration import check_apply_test
from wazuh_testing.tools.configuration import get_api_conf

# Marks

pytestmark = pytest.mark.server

# Variables

path = os.path.dirname(os.path.abspath(__file__))
rbac_sql_path = os.path.join(WAZUH_PATH, 'api', 'configuration', 'security', 'rbac.db')

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf_mode.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    # Add a new user in the RBAC database.
    con = sqlite3.connect(rbac_sql_path)
    cur = con.cursor()
    with open(os.path.join(test_data_path, 'schema_add_user.sql')) as f:
        sql = f.read()
        cur.executescript(sql)


def extra_configuration_after_yield():
    # Delete the test_user created in the RBAC database.
    con = sqlite3.connect(rbac_sql_path)
    cur = con.cursor()
    with open(os.path.join(test_data_path, 'schema_delete_user.sql')) as f:
        sql = f.read()
        cur.executescript(sql)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'rbac_white'},
    {'rbac_black'}
])
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_rbac_mode(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                   wait_for_start, get_api_details):
    '''
    description: Check if the 'RBAC' mode selected in 'api.yaml' is applied. This test creates a user
                 without any assigned permission. For this reason, when 'RBAC' is in 'white mode',
                 there is no endpoint that the user can execute, so the 'HTTP status code'
                 must be 403 ('forbidden'). On the other hand, when it is in 'black mode',
                 there is no endpoint that has it denied, so the status code must be 200 ('ok').

    wazuh_min_version: 4.2.0

    tier: 0

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
        - wait_for_start:
            type: fixture
            brief: Wait until the API starts.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Check that when the value of the 'rbac_mode' setting is set to 'white',
          the API forbids requests.
        - Verify that when the value of the 'rbac_mode' setting is set to 'black',
          the API requests are performed correctly.

    input_description: Different test cases are contained in an external YAML file (conf_mode.yaml)
                       which includes API configuration parameters (rbac operation modes).
                       Two 'SQL' scripts are also used to add (schema_add_user.sql)
                       and remove (schema_delete_user.sql) the testing user.

    expected_output:
        - r'200' ('OK' HTTP status code if 'rbac_white == True')
        - r'403' ('Forbidden' HTTP status code if 'rbac_white == False')

    tags:
        - rbac
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    rbac_white = get_configuration['security_config']['rbac_mode'] == 'white'
    api_details = get_api_details(user='test_user', password='wazuh')
    api_details['base_url'] += '/manager/info'

    # Request manager info.
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # If white mode, user can't access that information.
    if rbac_white:
        assert get_response.status_code == 403, f'Expected status code was 403, ' \
                                                f'but {get_response.status_code} was returned. ' \
                                                f'\nFull response: {get_response.text}'
    else:
        assert get_response.status_code == 200, f'Expected status code was 200, ' \
                                                f'but {get_response.status_code} was returned. ' \
                                                f'\nFull response: {get_response.text}'
