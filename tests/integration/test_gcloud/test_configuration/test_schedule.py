'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module executes at the periods
       set in the 'interval' tag.

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#interval

tags:
    - config
    - schedule
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_schedule_validate_parameters_warn
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

interval = ['1d', '1w', '1M']
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'schedule_conf.yaml')
force_restart_after_restoring = False

# configurations

daemons_handler_configuration = {'daemons': ['wazuh-modulesd']}
monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'INTERVAL': interval_value} for interval_value in interval),
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_schedule(get_configuration, configure_environment, reset_ossec_log, daemons_handler_module):
    '''
    description: Check if the 'gcp-pubsub' module is executed in the periods specified in the 'interval' tag.
                 For this purpose, the test will use different values for the 'interval' tag (a positive number
                 with a suffix character indicating a time unit, such as d (days), w (weeks), M (months)).
                 Finally, it will verify that the module starts by detecting the events that indicate
                 the validation of the parameters and vice versa.

    wazuh_min_version: 4.2.0

    tier: 1

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

    assertions:
        - Verify that the 'gcp-pubsub' module executes at the periods set in the 'interval' tag.

    input_description: Different test cases are contained in an external YAML file (schedule_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. Those are
                       combined with the scheduling values defined in the module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'.*at _sched_scan_validate_parameters.*: WARNING.*'

    tags:
        - scheduled
    '''

    str_interval = get_configuration['sections'][0]['elements'][3]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    tags_to_apply = get_configuration['tags'][0]

    # Warning log must appear in log (cause interval is not compatible with <day/month/week>)
    if (tags_to_apply == 'schedule_day' and 'M' not in str_interval) or \
       (tags_to_apply == 'schedule_wday' and 'w' not in str_interval) or \
       (tags_to_apply == 'schedule_time' and ('d' not in str_interval and 'w' not in str_interval)):
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                callback=callback_detect_schedule_validate_parameters_warn,
                                error_message='Did not receive expected '
                                              'at _sched_scan_validate_parameters(): WARNING:').result()
    # Warning is not suppose to appear
    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_schedule_validate_parameters_warn).result()
            raise AttributeError(f'Unexpected event {event}')
