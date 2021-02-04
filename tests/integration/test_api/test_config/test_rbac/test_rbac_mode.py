# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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
con = sqlite3.connect(rbac_sql_path)
cur = con.cursor()


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
    with open(os.path.join(test_data_path, 'schema_add_user.sql')) as f:
        sql = f.read()
        cur.executescript(sql)


def extra_configuration_after_yield():
    # Delete the test_user created in the RBAC database.
    with open(os.path.join(test_data_path, 'schema_delete_user.sql')) as f:
        sql = f.read()
        cur.executescript(sql)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'rbac_white'},
    {'rbac_black'}
])
def test_rbac_mode(tags_to_apply, get_configuration, configure_api_environment, restart_api,
                   wait_for_start, get_api_details):
    """Verify that the RBAC mode selected in api.yaml is applied.

    This test creates a user without any assigned permission.
    For this reason, when RBAC is in white mode, there is no
    endpoint that the user can execute, so the response must be 400.
    On the other hand, when it is in black mode, there is no endpoint
    that has it denied, so the answer must be 200.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    rbac_white = get_configuration['security_config']['rbac_mode'] == 'white'
    api_details = get_api_details(user='test_user', password='wazuh')
    api_details['base_url'] += '/manager/info'

    # Request manager info.
    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    # If white mode, user can't access that information.
    if rbac_white:
        assert get_response.status_code == 403, f'Expected status code was 403, ' \
            f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'
    else:
        assert get_response.status_code == 200, f'Expected status code was 200, ' \
            f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'
