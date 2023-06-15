'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if that module detects invalid configurations and indicates
       the location of the errors detected.

components:
    - gcloud

suite: configuration

targets:
    - agent
    - manager

daemons:
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html

tags:
    - invalid
    - config
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_schedule_validate_parameters_err, callback_detect_gcp_read_err, \
    callback_detect_gcp_wmodule_err, callback_detect_schedule_read_err
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service


# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'invalid_conf.yaml')
force_restart_after_restoring = False

# configurations

daemons_handler_configuration = {'daemons': ['wazuh-modulesd'], 'ignore_errors': True}
monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_invalid(get_configuration, configure_environment, reset_ossec_log, daemons_handler_module):
    '''
    description: Check if the 'gcp-pubsub' module detects invalid configurations. For this purpose, the test
                 will configure 'gcp-pubsub' using invalid configuration settings with different attributes.
                 Finally, it will verify that error events are generated indicating the source of the errors.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - reset_ossec_log:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that the 'gcp-pubsub' module generates error events when invalid configurations are used.

    input_description: Different test cases are contained in an external YAML file (invalid_conf.yaml) which
                       includes configuration settings for the 'gcp-pubsub' module. The GCP access credentials
                       can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'.*read_main_elements.*: ERROR.* Invalid element in the configuration.*'
        - r'.*at _sched_scan_validate_parameters.*: ERROR.*'
        - r'.*at sched_scan_read.*: ERROR.*'
        - r'.*at sched_scan_read.*: ERROR.*'

    tags:
        - invalid_settings
    '''
    tags_to_apply = get_configuration['tags'][0]

    if tags_to_apply == 'invalid_gcp_wmodule':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_gcp_wmodule_err,
                                error_message='Did not receive expected '
                                              'Invalid element in the configuration').result()
    elif tags_to_apply == 'invalid_day_wday':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_schedule_validate_parameters_err,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_schedule':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_schedule_read_err,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_gcp_read_err,
                                error_message='Did not receive expected '
                                              'wm_gcp_read(): ERROR:').result()
