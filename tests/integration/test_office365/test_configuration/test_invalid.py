# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.office365 import callback_detect_enabled_err, callback_detect_only_future_events_err, \
    callback_detect_interval_err, callback_detect_curl_max_size_err, callback_detect_tenant_id_err, \
    callback_detect_client_id_err, callback_detect_client_secret_err, callback_detect_subscription_err
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = True

# configurations

local_internal_options = {
    'wazuh_modules.debug': 2
}

cases = [
    # Case 1: Invalid enabled (version 4.3)
    {
        'params': {
            'ENABLED': 'invalid',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TENANT_ID': 'test_tenant',
            'CLIENT_ID': 'teat_client',
            'CLIENT_SECRET': 'test_secret',
            'SUBSCRIPTION': 'test_subscription'
        },
        'metadata': {
            'tags': 'invalid_enabled'
        }
    },
    # Case 2: Invalid only_future_events (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'invalid',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TENANT_ID': 'test_tenant',
            'CLIENT_ID': 'teat_client',
            'CLIENT_SECRET': 'test_secret',
            'SUBSCRIPTION': 'test_subscription'
        },
        'metadata': {
            'tags': 'invalid_only_future_events'
        }
    },
    # Case 3: Invalid interval (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '2d',
            'CURL_MAX_SIZE': '1024',
            'TENANT_ID': 'test_tenant',
            'CLIENT_ID': 'teat_client',
            'CLIENT_SECRET': 'test_secret',
            'SUBSCRIPTION': 'test_subscription'
        },
        'metadata': {
            'tags': 'invalid_interval'
        }
    },
    # Case 4: Invalid curl_max_size (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '-12',
            'TENANT_ID': 'test_tenant',
            'CLIENT_ID': 'teat_client',
            'CLIENT_SECRET': 'test_secret',
            'SUBSCRIPTION': 'test_subscription'
        },
        'metadata': {
            'tags': 'invalid_curl_max_size'
        }
    },
    # Case 5: Invalid tenant_id (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TENANT_ID': '',
            'CLIENT_ID': 'teat_client',
            'CLIENT_SECRET': 'test_secret',
            'SUBSCRIPTION': 'test_subscription'
        },
        'metadata': {
            'tags': 'invalid_tenant_id'
        }
    },
    # Case 6: Invalid client_id (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TENANT_ID': 'test_tenant',
            'CLIENT_ID': '',
            'CLIENT_SECRET': 'test_secret',
            'SUBSCRIPTION': 'test_subscription'
        },
        'metadata': {
            'tags': 'invalid_client_id'
        }
    },
    # Case 7: Invalid client_secret (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TENANT_ID': 'test_tenant',
            'CLIENT_ID': 'teat_client',
            'CLIENT_SECRET': '',
            'SUBSCRIPTION': 'test_subscription'
        },
        'metadata': {
            'tags': 'invalid_client_secret'
        }
    },
    # Case 8: Invalid subscription (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TENANT_ID': 'test_tenant',
            'CLIENT_ID': 'teat_client',
            'CLIENT_SECRET': 'test_secret',
            'SUBSCRIPTION': ''
        },
        'metadata': {
            'tags': 'invalid_subscription'
        }
    }
]
params = [case['params'] for case in cases]
metadata = [case['metadata'] for case in cases]

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# callbacks

callbacks = {
                'invalid_enabled': callback_detect_enabled_err,
                'invalid_only_future_events': callback_detect_only_future_events_err,
                'invalid_interval': callback_detect_interval_err,
                'invalid_curl_max_size': callback_detect_curl_max_size_err,
                'invalid_tenant_id': callback_detect_tenant_id_err,
                'invalid_client_id': callback_detect_client_id_err,
                'invalid_client_secret': callback_detect_client_secret_err,
                'invalid_subscription': callback_detect_subscription_err
            }


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get internal configuration."""
    return local_internal_options


# tests

def test_invalid(get_local_internal_options, configure_local_internal_options,
                 get_configuration, configure_environment, reset_ossec_log):
    """
    Checks if an invalid configuration is detected

    Using invalid configurations with different attributes,
    expect an error message and office365 unable to start.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration for testing.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        reset_ossec_log (fixture): Reset ossec.log and start a new monitor
    """
    # Configuration error -> ValueError raised
    try:
        control_service('restart')
    except ValueError:
        pass

    metadata = get_configuration.get('metadata')
    tags_to_apply = metadata['tags']

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callbacks[tags_to_apply],
                            accum_results=1,
                            error_message='Did not receive expected '
                                          'Invalid element in the configuration').result()
