'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'github' module allows you to collect all the 'audit logs' from GitHub using its API.
       Specifically, these tests will check if that module detects invalid configurations and indicates
       the location of the errors detected. The 'audit log' allows organization admins to quickly review
       the actions performed by members of your organization. It includes details such as who performed
       the action, what the action was, and when it was performed.

components:
    - github

suite: configuration

targets:
    - agent
    - manager

daemons:
    - wazuh-analysisd
    - wazuh-monitord
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://github.com/wazuh/wazuh-documentation/blob/develop/source/github/monitoring-github-activity.rst

tags:
    - github_configuration
'''
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
    '''
    description: Check if the 'github' module detects invalid configurations. For this purpose, the test
                 will configure that module using invalid configuration settings with different attributes.
                 Finally, it will verify that error events are generated indicating the source of the errors.

    wazuh_min_version: 4.3.0

    tier: 0

    parameters:
        - get_local_internal_options:
            type: fixture
            brief: Get internal configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - reset_ossec_log:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the 'github' module generates error events when invalid configurations are used.

    input_description: A configuration template (github_integration) is contained in an external YAML file
                       (wazuh_conf.yaml). That template is combined with different test cases defined in
                       the module. Those include configuration settings for the 'github' module.

    expected_output:
        - r'wm_github_read(): ERROR.* Invalid content for tag .*'
        - r'wm_github_read(): ERROR.* Empty content for tag .*'

    tags:
        - invalid_settings
    '''
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
