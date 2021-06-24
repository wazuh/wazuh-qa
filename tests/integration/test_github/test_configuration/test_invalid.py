# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.github import callback_detect_enabled_err, callback_detect_only_future_events_err, \
    callback_detect_interval_err, callback_detect_curl_max_size_err, callback_detect_time_delay_err, \
    callback_detect_org_name_err, callback_detect_api_token_err, callback_detect_event_type_err
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


# callbacks

callbacks = {
                'invalid_enabled': callback_detect_enabled_err,
                'invalid_only_future_events': callback_detect_only_future_events_err,
                'invalid_interval': callback_detect_interval_err,
                'invalid_curl_max_size': callback_detect_curl_max_size_err,
                'invalid_time_delay': callback_detect_time_delay_err,
                'invalid_org_name': callback_detect_org_name_err,
                'invalid_api_token': callback_detect_api_token_err,
                'invalid_event_type': callback_detect_event_type_err
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
    expect an error message and github unable to start.

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
