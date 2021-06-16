# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.office365 import callback_detect_enabled_err, callback_detect_only_future_events_err, callback_detect_interval_err, \
    callback_detect_curl_max_size_err, callback_detect_tenant_id_err, callback_detect_client_id_err, callback_detect_client_secret_err, \
    callback_detect_subscription_err, callback_detect_read_err
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


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def test_invalid(get_configuration, configure_environment, reset_ossec_log):
    """
    Checks if an invalid configuration is detected

    Using invalid configurations with different attributes,
    expect an error message and github unable to start.
    """
    # Configuration error -> ValueError raised
    try:
        control_service('restart')
    except ValueError:
        pass

    metadata = get_configuration.get('metadata')
    tags_to_apply = metadata['tags']

    if tags_to_apply == 'invalid_enabled':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_enabled_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'Invalid element in the configuration').result()
    elif tags_to_apply == 'invalid_only_future_events':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_only_future_events_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_interval':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_interval_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_curl_max_size':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_curl_max_size_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_tenant_id':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_tenant_id_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_client_id':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_client_id_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_client_secret':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_client_secret_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_subscription':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_subscription_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_read_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'wm_gcp_read(): ERROR:').result()
