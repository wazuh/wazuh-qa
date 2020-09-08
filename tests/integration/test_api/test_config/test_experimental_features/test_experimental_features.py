# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import requests

from wazuh_testing.tools.configuration import check_apply_test, get_api_conf

# Marks

pytestmark = pytest.mark.server


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
    {'experimental_enabled'},
    {'experimental_disabled'},
])
def test_experimental_features(tags_to_apply, get_configuration, configure_api_environment,
                               restart_api, wait_for_start, get_api_details):
    """Check if requests to an experimental endpoint are allowed according to the configuration.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    experimental = get_configuration['configuration']['experimental_features']
    api_details = get_api_details()
    api_details['base_url'] += '/experimental/syscollector/os'

    get_response = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

    if experimental:
        assert get_response.status_code == 200, f'Expected status code was 200, ' \
            f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'
    else:
        assert get_response.status_code == 404, f'Expected status code was 400, ' \
            f'but {get_response.status_code} was returned. \nFull response: {get_response.text}'
