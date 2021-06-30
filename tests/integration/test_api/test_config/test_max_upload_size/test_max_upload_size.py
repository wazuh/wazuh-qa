# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os.path import join, dirname, realpath
from uuid import uuid4

import pytest
import requests

from wazuh_testing.tools.configuration import check_apply_test, get_api_conf

# Marks

pytestmark = pytest.mark.server

# Configurations

test_data_path = join(dirname(realpath(__file__)), 'data')
configurations_path = join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply, expected_status_code', [
    ({'limitless_upload_size'}, 200),
    ({'low_upload_size'}, 413)
])
def test_max_upload_size(tags_to_apply, get_configuration, configure_api_environment, restart_api, wait_for_start,
                         get_api_details, expected_status_code):
    """Verify that a 413 status code is returned if the body is bigger than 'max_upload_size'.

    Calls to a PUT and a POST endpoint specifying a body. If the 'max_upload_size'
    is 0 (limitless), a 200 status code should be returned. If 'max_upload_size' is
    not limitless, both PUT and POST endpoints should fail when trying to send a
    bigger body.

    Args:
        tags_to_apply (set): Run test if match with a configuration identifier, skip otherwise.
        expected_status_code (int): Status code that should be returned when trying to run the endpoint.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    api_details = get_api_details()

    # Try to create a new group.
    response = requests.post(api_details['base_url'] + '/groups', headers=api_details['auth_headers'],
                             verify=False, json={'group_id': str(uuid4())})
    assert response.status_code == expected_status_code, f'Expected status code was {expected_status_code}, but ' \
                                                         f'{response.status_code} was returned: {response.json()}'

    # Try to upload a new CDB list.
    api_details['auth_headers']['Content-Type'] = 'application/octet-stream'
    response = requests.put(api_details['base_url'] + '/lists/files/new_cdb_list?overwrite=true',
                            headers=api_details['auth_headers'], verify=False,
                            files={'file': open(join(test_data_path, 'test_cdb_list'), 'r')})
    assert response.status_code == expected_status_code, f'Expected status code was {expected_status_code}, but ' \
                                                         f'{response.status_code} was returned: {response.json()}'
