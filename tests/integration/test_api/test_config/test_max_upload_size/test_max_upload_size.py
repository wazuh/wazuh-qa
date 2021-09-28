# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import string
from os.path import join, dirname, realpath
from random import choices

import pytest
import requests

from wazuh_testing.tools import API_LOG_FILE_PATH
from wazuh_testing.tools.configuration import check_apply_test, load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]


# Configurations

daemons_handler_configuration = {'daemons': ['wazuh-apid']}
file_to_monitor = API_LOG_FILE_PATH
test_data_path = join(dirname(realpath(__file__)), 'data')
configurations_path = join(test_data_path, 'wazuh_max_upload_size.yaml')

parameters = [
    {'MAX_UPLOAD_SIZE': 0},
    {'MAX_UPLOAD_SIZE': 5},
    {'MAX_UPLOAD_SIZE': 40},
    {'MAX_UPLOAD_SIZE': 40},
]

metadata = [
    {'max_upload_size': 0, 'content_size': 100},
    {'max_upload_size': 5, 'content_size': 20},
    {'max_upload_size': 40, 'content_size': 10},
    {'max_upload_size': 40, 'content_size': 500},
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"max_upload_size_{x['max_upload_size']}-content_size_{x['content_size']}" for x in metadata]


# Fixtures

@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

@pytest.fixture(scope='module')
def restart_required_api_wazuh():
    """Restart API-required services and stop them all at the end of the test."""
    required_api_daemons = ['wazuh-modulesd', 'wazuh-analysisd', 'wazuh-execd', 'wazuh-db', 'wazuh-remoted']

    for daemon in required_api_daemons:
        control_service('restart', daemon=daemon)

    truncate_file(file_to_monitor)

    yield

    for daemon in required_api_daemons:
        control_service('stop', daemon=daemon)


def create_group_name(length):
    """Return a random string with 'length' characters and digits.

    Args:
        length (int): Number of characters that the string should contain.

    Returns:
        string: String with 'length' random characters and digits.
    """
    return ''.join(choices(string.ascii_uppercase + string.digits, k=length))


def create_cdb_list(min_length):
    """Create a string formatted as a CDB list which is at least 'min_length' long

    Args:
        min_length (int): Minimum number of characters that the string should contain. More characters could
        be returned if needed for a correct dict formatting.


    Returns:
        string: String with at least 'min_length' characters formatted as a CDB list.
    """
    cdb_content = ''
    key_counter = 0

    while len(cdb_content) < min_length:
        cdb_content = cdb_content + f'{key_counter}:\n'
        key_counter += 1

    return cdb_content


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'test_upload_size'}
])
def test_max_upload_size(tags_to_apply, get_configuration, configure_api_environment, restart_required_api_wazuh,
                         file_monitoring, daemons_handler, wait_for_start, get_api_details):
    """Verify that a 413 status code is returned if the body is bigger than 'max_upload_size'.

    Calls to a PUT and a POST endpoint specifying a body. If the 'max_upload_size'
    is 0 (limitless), a 200 status code should be returned. If 'max_upload_size' is
    not limitless, both PUT and POST endpoints should fail when trying to send a
    bigger body.

    Args:
        tags_to_apply (set): Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    api_details = get_api_details()
    content_size = get_configuration['metadata']['content_size']
    max_upload_size = get_configuration['metadata']['max_upload_size']
    expected_status_code = 200 if max_upload_size == 0 or max_upload_size > content_size else 413

    group_name = create_group_name(content_size)

    # Try to create a new group.
    response = requests.post(api_details['base_url'] + '/groups', headers=api_details['auth_headers'],
                             verify=False, json={'group_id': group_name})
    assert response.status_code == expected_status_code, f"Expected status code was {expected_status_code}, but " \
                                                         f"{response.status_code} was returned: {response.json()}"

    if expected_status_code == 200:
        # Try to delete the group created before.
        response = requests.delete(api_details['base_url'] + f'/groups?groups_list={group_name}',
                                   headers=api_details['auth_headers'], verify=False)

    # Try to upload a new CDB list.
    api_details['auth_headers']['Content-Type'] = 'application/octet-stream'
    response = requests.put(api_details['base_url'] + '/lists/files/new_cdb_list?overwrite=true',
                            headers=api_details['auth_headers'], verify=False,
                            data=create_cdb_list(content_size).encode())
    assert response.status_code == expected_status_code, f"Expected status code was {expected_status_code}, but " \
                                                         f"{response.status_code} was returned: {response.json()}"
