'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module gets the GCP logs at the intervals
       specified in the configuration and sleeps up to them.

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#interval

tags:
    - scan
    - scheduled
    - interval
'''
import datetime
import os
import sys
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_start_fetching_logs, callback_detect_start_gcp_sleep
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = ['30s', '1m']
pull_on_start = 'yes'
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
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'PULL_ON_START': pull_on_start,
               'MAX_MESSAGES': max_messages, 'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'INTERVAL': interval_value} for interval_value in interval),
                       modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Preparing

truncate_file(LOG_FILE_PATH)

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_interval(get_configuration, configure_environment, reset_ossec_log, daemons_handler, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module starts to pull logs at the periods set in the configuration
                 by the 'interval' tag. For this purpose, the test will use different intervals and check if
                 the 'sleep' event is triggered and matches with the set interval. Finally, the test will wait
                 the time specified in that interval and verify that the 'fetch' event is generated.

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
        - Verify that the 'gcp-pubsub' module sleeps between the intervals specified in the configuration.
        - Verify that the 'gcp-pubsub' module starts to pull logs at the intervals specified in the configuration.

    input_description: A test case (ossec_conf) is contained in an external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. That is
                       combined with the interval values defined in the module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'.*wm_gcp_main.*: DEBUG.* Sleeping until.*'
        - r'wm_gcp_main(): DEBUG.* Starting fetching of logs.'

    tags:
        - logs
        - scheduled
    '''
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    if 'm' in str_interval:
        time_interval *= 60

    start_time = time.time()
    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 error_message='Did not receive expected '
                                                               '"Sleeping until ..." event').result()

    test_now = datetime.datetime.now()
    next_scan_time_spl = next_scan_time_log.split(" ")
    date = next_scan_time_spl[0].split("/")
    hour = next_scan_time_spl[1].split(":")
    next_scan_time = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(hour[0]), int(hour[1]),
                                       int(hour[2]))
    diff_time_log = int((next_scan_time - test_now).total_seconds())
    assert time_interval - diff_time_log <= 25

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                            callback=callback_detect_start_fetching_logs,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
    end_time = time.time()
    diff_time = int(end_time - start_time)
    assert time_interval - diff_time <= 10