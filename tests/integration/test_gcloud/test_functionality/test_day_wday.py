'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module gets the GCP logs at the date-time
       specified in the configuration and sleeps up to it.

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#day
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#wday
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html#time

tags:
    - week_day
    - scan
    - scheduled
    - interval
'''
import datetime
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_start_gcp_sleep
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_schedule_conf.yaml')
force_restart_after_restoring = False
interval = '1h'
pull_on_start = 'no'
max_messages = 100
logging = "info"
monthDays = {"1": 31, "2": 28, "3": 31, "4": 30, "5": 31, "6": 30, "7": 31, "8": 31, "9": 30, "10": 31, "11": 30,
             "12": 31}


def set_datetime_info():
    """Set datetime info globally."""
    global today, day, wday, day_time

    today = datetime.datetime.today()
    day = today.day
    wday = today.strftime('%A')
    day_time = today.strftime("%H:%M")


set_datetime_info()

# configurations

daemons_handler_configuration = {'daemons': ['wazuh-modulesd']}
monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'DAY': day, 'WDAY': wday, 'DAY_TIME': day_time,
               'WDAY_TIME': day_time, 'TIME': day_time, 'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
                       modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply', [
    ({'ossec_day_conf'}),
    ({'ossec_wday_conf'}),
    ({'ossec_time_conf'})
])
@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_day_wday(tags_to_apply, get_configuration, configure_environment, reset_ossec_log, daemons_handler_module,
                  wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module starts to pull logs according to the day of the week,
                 of the month, or time set in the configuration. For this purpose, the test will use
                 different values for the 'day', 'wday', and 'time' tags (depending on the test case).
                 Then, it will check that the 'sleep' event is triggered and matches with the set interval.
                 Finally, the test will travel in time to the specified interval and verify that
                 the 'fetch' event is generated.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
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
        - Verify that the 'gcp-pubsub' module sleeps up to the date-time specified in the configuration.
        - Verify that the 'gcp-pubsub' module starts to pull logs at the date-time specified in the configuration.

    input_description: Tree test cases are contained in an external YAML file (wazuh_schedule_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. Those are
                       combined with the scheduling values defined in the module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'.*wm_gcp_main.*: DEBUG.* Sleeping until.*'
        - r'wm_gcp_main(): DEBUG.* Starting fetching of logs.'

    tags:
        - logs
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_start_gcp_sleep,
                            error_message='Did not receive expected "Sleeping until ..." event').result()


@pytest.mark.parametrize('tags_to_apply', [
    ({'ossec_day_multiple_conf'}),
    pytest.param({'ossec_wday_multiple_conf'}, marks=pytest.mark.xfail(reason="Unstable because of wazuh/wazuh#15255")),
    ({'ossec_time_multiple_conf'})
])
@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_day_wday_multiple(tags_to_apply, get_configuration, configure_environment, reset_ossec_log,
                           daemons_handler_module, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module calculates the next scan correctly using time intervals
                 greater than one month, one week, or one day. For this purpose, the test will use different
                 values for the 'day', 'wday', and 'time' tags (depending on the test case). Finally, it
                 will check that the 'sleep' event is triggered and matches with the set interval.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
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
        - Verify that the 'gcp-pubsub' module calculates the next scan correctly from
          the date-time and interval values specified in the configuration.

    input_description: Tree test cases are contained in an external YAML file (wazuh_schedule_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. Those are
                       combined with the scheduling values defined in the module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - r'.*wm_gcp_main.*: DEBUG.* Sleeping until.*'

    tags:
        - logs
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    interval, unit = get_configuration['sections'][0]['elements'][4]['interval']['value']
    interval = int(interval)
    kwargs = {'days': 0 if unit != 'd' else interval, 'weeks': 0 if unit != 'w' else interval}
    # Update datetime info globally
    set_datetime_info()
    # Get the expected date before the test run to avoid a day difference with Wazuh's scheduled scan
    expected_next_scan_date = today + datetime.timedelta(**kwargs)

    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 error_message='Did not receive expected '
                                                               '"Sleeping until ..." event').result()

    next_scan_time_spl = next_scan_time_log.split(" ")
    year, month, day = [int(_) for _ in next_scan_time_spl[0].split("/")]
    hour, minute, second = [int(_) for _ in next_scan_time_spl[1].split(":")]

    next_scan_time = datetime.datetime(year, month, day, hour, minute, second)
    next_scan_time_weekday = next_scan_time.strftime('%A')

    if tags_to_apply == {'ossec_day_multiple_conf'}:
        if today.month + interval <= 12:
            expected_month = today.month + interval
        else:
            expected_month = (today.month + interval) % 12

        if today.day > monthDays[str(expected_month)]:
            expected_month = expected_month + 1

        assert next_scan_time.month == expected_month
    else:
        assert next_scan_time.day == expected_next_scan_date.day
        if tags_to_apply == {'ossec_wday_multiple_conf'}:
            assert next_scan_time_weekday == wday
