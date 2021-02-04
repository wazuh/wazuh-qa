# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import requests

from wazuh_testing import global_parameters
from wazuh_testing.api import callback_detect_api_start
from wazuh_testing.tools import API_LOG_FILE_PATH
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.server


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(API_LOG_FILE_PATH)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('expected_exception, tags_to_apply', [
    (False, {'conf_1'}),
    (True, {'conf_2'}),
])
def test_host_port(expected_exception, tags_to_apply,
                   get_configuration, configure_api_environment, restart_api, get_api_details):
    """Try different host and port configurations.

    Apply multiple combinations of host and port, verify that aiohttp correctly publishes
    that value in the api.log and check that the request returns the expected value.

    Parameters
    ----------
    expected_exception : bool
        True if an exception must be raised, false otherwise.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    host = get_configuration['configuration']['host']
    port = get_configuration['configuration']['port']

    # Check that expected host and port are shown in api.log
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 10,
                                    callback=callback_detect_api_start,
                                    error_message='Did not receive expected "Listening on ..." event').result()
    assert event == f"{host}:{port}", f'Expected API log was "{host}:{port}", but the returned one is "{event}".'

    # Perform actual request and verify if response code is the expected one.
    try:
        api_details = get_api_details(host=host, port=port, timeout=5)
        r = requests.get(api_details['base_url'], headers=api_details['auth_headers'], verify=False)

        assert not expected_exception, 'Exception was expected but not received.'
        assert r.status_code == 200, f'Expected status code was 200, but {r.status_code} was received.'
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):
        assert expected_exception, 'Request got unexpected exception.'
