'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module gets only the GCP events whose
       logging level matches the one specified in the 'logging' tag.

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
import wazuh_testing.tools.configuration as conf
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = '25s'
pull_on_start = 'yes'
max_messages = 100
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
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'MODULE_NAME': __name__}
log_levels = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']

p, m = generate_params(extra_params=conf_params,
                       apply_to_all=(),
                       modes=monitoring_modes)

configurations = conf.load_wazuh_configurations(configurations_path, __name__,
                                                params=p, metadata=m)


# fixtures
@pytest.fixture(scope='module', params=[
    {'wazuh_modules.debug': 0,
     'monitord.rotate_log': 0, 'monitord.day_wait': 0,
     'monitord.keep_log_days': 0, 'monitord.size_rotate': 0},
    {'wazuh_modules.debug': 1,
     'monitord.rotate_log': 0, 'monitord.day_wait': 0,
     'monitord.keep_log_days': 0, 'monitord.size_rotate': 0},
    {'wazuh_modules.debug': 2,
     'monitord.rotate_log': 0, 'monitord.day_wait': 0,
     'monitord.keep_log_days': 0, 'monitord.size_rotate': 0}
])
def get_local_internal_options(request):
    """Get internal configuration."""
    return request.param


@pytest.fixture(scope='module')
def configure_local_internal_options_module(get_local_internal_options):
    """Fixture to configure the local internal options file.

    It uses the test fixture get_local_internal_options. This should be
    a dictionary wich keys and values corresponds to the internal option configuration, For example:
    local_internal_options = {'monitord.rotate_log': '0', 'syscheck.debug': '0' }
    """
    local_internal_options = get_local_internal_options

    backup_local_internal_options = conf.get_local_internal_options_dict()

    conf.set_local_internal_options_dict(local_internal_options)
    import wazuh_testing.tools.services as services
    services.restart_wazuh_daemon('wazuh-modulesd')

    yield

    conf.set_local_internal_options_dict(backup_local_internal_options)


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
@pytest.mark.parametrize('publish_messages', [
    (['{level} GCP'.format(level=log_level) for log_level in log_levels]),
], indirect=True)
def test_logging(get_configuration, configure_environment, reset_ossec_log,
                 publish_messages, configure_local_internal_options_module,
                 daemons_handler_module, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module generates logs according to the debug level set for wazuh_modules.
                 For this purpose, the test will use different debug levels (depending on the test case) and
                 gets the GCP events. Finally, the test will verify that the type of all retrieved events matches
                 the one specified in the configuration.

    wazuh_min_version: 4.4.0

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
        - configure_local_internal_options_module:
            type: fixture
            brief: Fixture to modify the local_internal_options.conf file
                   and restart modulesd.
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - wait_for_gcp_start:
            type: fixture
            brief: Wait for the 'gpc-pubsub' module to start.

    assertions:
        - Verify that the logging level of retrieved GCP events matches the one specified in the 'logging' tag.
        - Verify that the module outputs messages that correspond to the logging level.

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
    logging_opt = int([x[-2] for x in conf.get_wazuh_local_internal_options()
                      if x.startswith('wazuh_modules.debug')][0])
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    mandatory_keywords = {}
    if logging_opt == 0:
        skipped_keywords = ['DEBUG:']
    else:
        skipped_keywords = []
        mandatory_keywords = {'DEBUG:': 0, 'INFO': 0}

    timeout = global_parameters.default_timeout + time_interval + 5 if \
        logging_opt != 0 else 5

    for _ in range(12):
        try:
            event = wazuh_log_monitor.start(
                timeout=timeout, callback=callback_detect_all_gcp,
                accum_results=1, error_message='Did not receive expected '
                'wazuh-modulesd:gcp-pubsub[]').result()
        except TimeoutError:
            if logging_opt == 0:
                continue
            else:
                raise
        for k in mandatory_keywords.keys():
            if k in event:
                mandatory_keywords[k] += 1

        for key in skipped_keywords:
            assert key not in event
    assert all(mandatory_keywords.values())
