'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module gets only the GCP events whose
       logging level matches the one specified in the 'logging' tag.

tier: 0

modules:
    - gcloud

components:
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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#logging

tags:
    - logging
    - logs
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_all_gcp
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = '25s'
pull_on_start = 'yes'
max_messages = 100
logging = ['info', 'debug', 'warning', 'error', 'critical']
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
                       apply_to_all=({'LOGGING': logging_value} for logging_value in logging),
                       modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
@pytest.mark.parametrize('publish_messages', [
    ['- DEBUG - GCP message' for _ in range(5)]
], indirect=True)
def test_logging(get_configuration, configure_environment, reset_ossec_log, publish_messages, daemons_handler, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module generates logs according to the set type in the 'logging' tag.
                 For this purpose, the test will use different logging levels (depending on the test case) and
                 gets the GCP events. Finally, the test will verify that the type of all retrieved events matches
                 the one specified in the configuration.

    wazuh_min_version: 4.2.0

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
        - Verify that the logging level of retrieved GCP events matches the one specified in the 'logging' tag.

    input_description: A test case (ossec_conf) is contained in an external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. That is
                       combined with the logging levels defined in the module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'.*wazuh-modulesd:gcp-pubsub.*'

    tags:
        - logs
        - scheduled
    '''
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    logging_opt = get_configuration['sections'][0]['elements'][6]['logging']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    if logging_opt == 'info':
        key_words = ['- DEBUG -', '- WARNING -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'debug':
        key_words = ['- INFO -', '- WARNING -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'warning':
        key_words = ['- INFO -', '- DEBUG -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'warning':
        key_words = ['- INFO -', '- DEBUG -', '- WARNING -', '- CRITICAL -']
    else:
        key_words = ['- INFO -', '- DEBUG -', '- WARNING -', '- ERROR -']

    for nevents in range(0, 12):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval + 5,
                                        callback=callback_detect_all_gcp,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                      'wazuh-modulesd:gcp-pubsub[]').result()

        for key in key_words:
            assert key not in event
