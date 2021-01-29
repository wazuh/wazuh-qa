# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import requests
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf

# Marks

pytestmark = pytest.mark.server

# Variables

test_directories = [os.path.join(PREFIX, 'test_cert')]

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
    {'https_disabled'},
    {'https_enabled'},
])
def test_https(tags_to_apply, get_configuration, configure_api_environment,
               restart_api, wait_for_start, get_api_details):
    """Check that the API works with http and https protocols.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    https = get_configuration['configuration']['https']['enabled']
    api_details = get_api_details(protocol='https' if https else 'http')

    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    assert get_response.status_code == 200, f'Expected status code was 200, but {get_response.status_code} was ' \
                                            f'returned. \nFull response: {get_response.text}'
