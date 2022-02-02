'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the 'gcp-pubsub' module gets the GCP logs at the date-time
       specified in the configuration and sleeps up to it.

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
from wazuh_testing.gcloud import callback_detect_start_fetching_logs, callback_detect_start_gcp_sleep
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = '1h'
pull_on_start = 'no'
max_messages = 100
logging = "info"

today = datetime.date.today()
day = today.day

weekDays = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
monthDays = {"1": 31, "2": 28, "3": 31, "4": 30, "5": 31, "6": 30, "7": 31, "8": 31, "9": 30, "10": 31, "11": 30, "12": 31}
wday = weekDays[today.weekday()]

now = datetime.datetime.now()
day_time = now.strftime("%H:%M")

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_schedule_conf.yaml')
force_restart_after_restoring = False

# configurations

daemons_handler_configuration = {'daemons': ['wazuh-modulesd']}
monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'LOGGING': logging, 'DAY': day, 'WDAY': wday, 'DAY_TIME': day_time,
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
def test_day_wday(tags_to_apply, get_configuration, configure_environment, reset_ossec_log, daemons_handler, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module starts to pull logs according to the day of the week,
                 of the month, or time set in the configuration. For this purpose, the test will use
                 different values for the 'day', 'wday', and 'time' tags (depending on the test case).
                 Then, it will check that the 'sleep' event is triggered and matches with the set interval.
                 Finally, the test will travel in time to the specified interval and verify that
                 the 'fetch' event is generated.

    wazuh_min_version: 4.2.0

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
    def get_next_scan(next_scan_time: str):
        next_scan_time = next_scan_time_log.split()
        date = next_scan_time[0].split('/')
        hour = next_scan_time[1].split(':')

        date_before = datetime.datetime.now()

        date_after = datetime.datetime(int(date[0]), int(date[1]), int(date[2]),
                                       int(hour[0]), int(hour[1]), int(hour[2]))
        diff_time = (date_after - date_before).total_seconds()

        return int(diff_time)

    check_apply_test(tags_to_apply, get_configuration['tags'])

    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 error_message='Did not receive expected '
                                                               '"Sleeping until ..." event').result()


@pytest.mark.parametrize('tags_to_apply', [
    ({'ossec_day_multiple_conf'}),
    ({'ossec_wday_multiple_conf'}),
    ({'ossec_time_multiple_conf'})
])

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_day_wday_multiple(tags_to_apply, get_configuration, configure_environment, reset_ossec_log, daemons_handler, wait_for_gcp_start):
    '''
    description: Check if the 'gcp-pubsub' module calculates the next scan correctly using time intervals
                 greater than one month, one week, or one day. For this purpose, the test will use different
                 values for the 'day', 'wday', and 'time' tags (depending on the test case). Finally, it
                 will check that the 'sleep' event is triggered and matches with the set interval.

    wazuh_min_version: 4.2.0

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

    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 error_message='Did not receive expected '
                                                               '"Sleeping until ..." event').result()

    next_scan_time_spl = next_scan_time_log.split(" ")
    date = next_scan_time_spl[0].split("/")
    hour = next_scan_time_spl[1].split(":")

    next_scan_time = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(hour[0]), int(hour[1]),
                                       int(hour[2]))

    if tags_to_apply == {'ossec_day_multiple_conf'}:
        if today.month + time_interval <= 12:
            expected_month = today.month + time_interval
        else:
            expected_month = (today.month + time_interval) % 12

        if today.day > monthDays[str(expected_month)]:
            expected_month = expected_month + 1

        assert next_scan_time.month == expected_month

    if tags_to_apply == {'ossec_wday_multiple_conf'}:
        assert weekDays[next_scan_time.weekday()] == wday
        assert next_scan_time.day == (today + datetime.timedelta(weeks=time_interval)).day

    if tags_to_apply == {'ossec_time_multiple_conf'}:
        assert next_scan_time.day == (today + datetime.timedelta(days=time_interval)).day
