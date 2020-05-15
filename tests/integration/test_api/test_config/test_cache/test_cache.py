# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

import pytest
import requests

from wazuh_testing.fim import create_file, delete_file, REGULAR, WAZUH_PATH
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf

# Marks

pytestmark = pytest.mark.server


# Variables

rules_directory = os.path.join(WAZUH_PATH, 'ruleset', 'rules')
test_file = 'api_test.xml'


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions
def extra_configuration_before_yield():
    # Delete file before running the test if it exists.
    delete_file(rules_directory, test_file)


def extra_configuration_after_yield():
    # Delete file created in the test.
    delete_file(rules_directory, test_file)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'cache_enabled'},
    {'cache_disabled'}
])
def test_cache(tags_to_apply, get_configuration, configure_api_environment, restart_api,
               wait_for_start, get_api_details):
    """Verify that the stored response is returned when cache is enabled.

    Calls to rules endpoints can be cached. This test verifies that the result
    of the first call to a rule endpoint is equal to the second within a period
    established in the configuration, even though a new file has been created
    during the process.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    cache = get_configuration['configuration']['cache']['enabled']
    api_details = get_api_details()
    api_details['base_url'] += '/rules/files'

    # Request number of rules files before creating a new one.
    first_response = requests.get(api_details['base_url'],
                                  headers=api_details['auth_headers'],
                                  verify=False).json()['data']['total_affected_items']

    # Create a new file inside /var/ossec/ruleset/rules
    create_file(REGULAR, rules_directory, test_file)

    # Request again the number of rules files after creating a new one.
    second_response = requests.get(api_details['base_url'],
                                   headers=api_details['auth_headers'],
                                   verify=False).json()['data']['total_affected_items']

    # If cache is enabled, number of files should be the same in the first and second response even with a new one.
    if cache:
        assert first_response == second_response, 'Total_affected_items should be equal in first and second response ' \
                                                  'when cache is enabled.'

        # Wait until cache expires (10 seconds) and verify that new response is updated.
        time.sleep(11)
        third_response = requests.get(api_details['base_url'],
                                      headers=api_details['auth_headers'],
                                      verify=False).json()['data']['total_affected_items']
        assert first_response + 1 == third_response, 'Cache should have expired but the response is still outdated.'

    else:
        # Verify that the second response is updated when cache is disabled.
        assert first_response + 1 == second_response, 'Total_affected_items should be smaller in first response if ' \
                                                      'cache is disabled.'
