# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.github import callback_detect_enabled_err, callback_detect_only_future_events_err, \
    callback_detect_interval_err, callback_detect_curl_max_size_err, callback_detect_time_delay_err, \
    callback_detect_org_name_err, callback_detect_api_token_err, callback_detect_event_type_err, \
    callback_detect_read_err
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
            'TIME_DELAY': '1s',
            'ORG_NAME': 'dummy',
            'API_TOKEN': 'token',
            'EVENT_TYPE': 'all'
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
            'TIME_DELAY': '1s',
            'ORG_NAME': 'dummy',
            'API_TOKEN': 'token',
            'EVENT_TYPE': 'all'
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
            'INTERVAL': '-5s',
            'CURL_MAX_SIZE': '1024',
            'TIME_DELAY': '1s',
            'ORG_NAME': 'dummy',
            'API_TOKEN': 'token',
            'EVENT_TYPE': 'all'
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
            'TIME_DELAY': '1s',
            'ORG_NAME': 'dummy',
            'API_TOKEN': 'token',
            'EVENT_TYPE': 'all'
        },
        'metadata': {
            'tags': 'invalid_curl_max_size'
        }
    },
    # Case 5: Invalid time_delay (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TIME_DELAY': '7k',
            'ORG_NAME': 'dummy',
            'API_TOKEN': 'token',
            'EVENT_TYPE': 'all'
        },
        'metadata': {
            'tags': 'invalid_time_delay'
        }
    },
    # Case 6: Invalid org_name (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TIME_DELAY': '1s',
            'ORG_NAME': '',
            'API_TOKEN': 'token',
            'EVENT_TYPE': 'all'
        },
        'metadata': {
            'tags': 'invalid_org_name'
        }
    },
    # Case 7: Invalid api_token (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TIME_DELAY': '1s',
            'ORG_NAME': 'dummy',
            'API_TOKEN': '',
            'EVENT_TYPE': 'all'
        },
        'metadata': {
            'tags': 'invalid_api_token'
        }
    },
    # Case 8: Invalid event_type (version 4.3)
    {
        'params': {
            'ENABLED': 'yes',
            'ONLY_FUTURE_EVENTS': 'yes',
            'INTERVAL': '1m',
            'CURL_MAX_SIZE': '1024',
            'TIME_DELAY': '1s',
            'ORG_NAME': 'dummy',
            'API_TOKEN': 'token',
            'EVENT_TYPE': 'invalid'
        },
        'metadata': {
            'tags': 'invalid_event_type'
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
    elif tags_to_apply == 'invalid_time_delay':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_time_delay_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_org_name':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_org_name_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_api_token':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_api_token_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_event_type':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_event_type_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_read_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'wm_gcp_read(): ERROR:').result()
