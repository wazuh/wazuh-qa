'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module gets GCP messages when it starts
       if the 'pull_on_start' tag is set to 'yes', and sleeps otherwise.

components:
    - gcloud

suite: functionality

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#pull-on-start

tags:
    - pull
    - config
    - on_start
    - scan
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_start_fetching_logs, callback_detect_start_gcp_sleep
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = '30s'
pull_on_start = ['yes', 'no']
max_messages = 100
logging = "info"
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = False

# configurations

daemons_handler_configuration = {'daemons': ['wazuh-modulesd']}
monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'INTERVAL': interval,
               'MAX_MESSAGES': max_messages, 'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'PULL_ON_START': pull_on_start_value} for pull_on_start_value in pull_on_start),
                       modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_pull_on_start(get_configuration, configure_environment,
                       daemons_handler_module, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module pulls messages when starting if the 'pull_on_start' is
                 set to 'yes', or sleeps up to the next interval if that one is set to 'no'. For this
                 purpose, the test will use the possible values for that tag ('yes' and 'no'). Then, it
                 will wait for the 'fetching' event if the pull on start opction is enabled. Otherwise,
                 the test will verify that the 'sleep' event is generated, and the 'fetching' event is not.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - wait_for_gcp_start:
            type: fixture
            brief: Wait for the 'gpc-pubsub' module to start.

    assertions:
        - Verify that the 'gcp-pubsub' module gets GCP messages when it starts
          if the 'pull_on_start' tag is set to 'yes'.
        - Verify that the 'gcp-pubsub' module sleeps up to the next interval when it starts
          if the 'pull_on_start' tag is set to 'no'.

    input_description: A test case (ossec_conf) is contained in an external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. That is
                       combined with the 'pull_on_start' values defined in the module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'wm_gcp_main(): DEBUG.* Starting fetching of logs.'
        - r'.*wm_gcp_main.*: DEBUG.* Sleeping until.*' (when 'pull_on_start=no')

    tags:
        - logs
        - scheduled
    '''
    pull_start = get_configuration['sections'][0]['elements'][3]['pull_on_start']['value'] == 'yes'
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    if pull_start:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_start_fetching_logs,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              '"Starting fetching of logs" event').result()
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_start_gcp_sleep,
                                error_message='Did not receive expected '
                                              '"Sleeping until ..." event')
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_start_fetching_logs)
            raise AttributeError(f'Unexpected event {event}')

        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                callback=callback_detect_start_fetching_logs,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              '"Starting fetching of logs" event').result()
