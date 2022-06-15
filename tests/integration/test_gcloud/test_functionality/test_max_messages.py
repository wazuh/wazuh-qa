'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module gets GCP messages up to the limit
       set in the 'max_messages' tag on the same operation when the number
       of them exceeds that limit.

components:
    - gcloud

suite: functionality

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#max-messages

tags:
    - limits
    - scan
    - maximum
'''
from itertools import count
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_start_fetching_logs, callback_received_messages_number
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file
from google.cloud import pubsub_v1

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = '25s'
pull_messages_timeout = global_parameters.default_timeout + 60
pull_on_start = 'no'
max_messages = 100
count_message = 0
logging = 'info'
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = False

# configurations

daemons_handler_configuration = {'daemons': ['wazuh-analysisd', 'wazuh-modulesd']}
monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
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
@pytest.mark.parametrize('publish_messages', [
    ['- DEBUG - GCP message' for _ in range(30)],
    ['- DEBUG - GCP message' for _ in range(100)],
    ['- DEBUG - GCP message' for _ in range(120)]
], indirect=True)
def test_max_messages(get_configuration, configure_environment, reset_ossec_log, publish_messages, daemons_handler, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module pulls a message number less than or equal to the limit set
                 in the 'max_messages' tag. For this purpose, the test will use a fixed limit and generate a
                 number of GCP events lower and upper than the limit (depending on the test case). Then, it
                 will wait for the 'fetching' event, and finally, the test will verify that, if the message
                 number exceeds that limit, the module will only pull messages up to the limit, and the rest
                 will be pulled in successive iterations, and if not, the module will pull all messages in
                 the same operation.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - publish_messages:
            type: list
            brief: List of testing GCP logs.
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - wait_for_gcp_start:
            type: fixture
            brief: Wait for the 'gpc-pubsub' module to start.

    assertions:
        - Verify that the 'gcp-pubsub' module pulls all GCP messages in one operation if
          the number of them does not exceed the limit set in the 'max_messages' tag.
        - Verify that the 'gcp-pubsub' module pulls GCP messages up to the limit set
          in the 'max_messages' tag when the number of them exceeds that limit, and
          the remaining ones are pulled in the successive operations.

    input_description: A test case (ossec_conf) is contained in an external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. That is
                       combined with the message limit defined in the module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'wm_gcp_main(): DEBUG.* Starting fetching of logs.'
        - r'.*wm_gcp_run.*: INFO.* INFO: Received and acknowledged .* messages'

    tags:
        - logs
        - scheduled
    '''
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    # Wait till the fetch starts
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                            callback=callback_detect_start_fetching_logs,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event')

    numbers_pulled = wazuh_log_monitor.start(timeout=pull_messages_timeout,
                                             callback=callback_received_messages_number,
                                             error_message='Did not receive expected '
                                                           '- INFO - Received and acknowledged x messages').result()
    if publish_messages <= max_messages:
        # GCP might log messages from sources other than ourselves
        for number_pulled in numbers_pulled:
            if int(number_pulled) != 0:
                if (int(number_pulled) >= publish_messages):
                    count_message += 1
                assert int(number_pulled) <= max_messages
        assert count_message >=1
    else:
        for number_pulled in numbers_pulled:
            if int(number_pulled) != 0:
                assert int(number_pulled) <= max_messages
