# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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
wday = weekDays[today.weekday()]

now = datetime.datetime.now()
day_time = now.strftime("%H:%M")

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_schedule_conf.yaml')
force_restart_after_restoring = True

# configurations

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
def test_day_wday(tags_to_apply, get_configuration, configure_environment,
                  restart_wazuh, wait_for_gcp_start):
    """
    These tests verify the module starts to pull according to the day of the week
    or month and time.
    """
    def get_next_scan(next_scan_time: str):
        next_scan_time = next_scan_time_log.split()
        date = next_scan_time[0].split('/')
        hour = next_scan_time[1].split(':')

        date_before = datetime.datetime.now()

        date_after = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(hour[0]), int(hour[1]), int(hour[2]))
        diff_time = (date_after - date_before).total_seconds()

        return int(diff_time)

    check_apply_test(tags_to_apply, get_configuration['tags'])

    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 error_message='Did not receive expected '
                                                               '"Sleeping until ..." event').result()

    TimeMachine.travel_to_future(datetime.timedelta(seconds=get_next_scan(next_scan_time_log)))

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callback_detect_start_fetching_logs,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event')


@pytest.mark.parametrize('tags_to_apply', [
    ({'ossec_day_multiple_conf'}),
    ({'ossec_wday_multiple_conf'}),
    ({'ossec_time_multiple_conf'})
])
@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_day_wday_multiple(tags_to_apply, get_configuration, configure_environment,
                           restart_wazuh, wait_for_gcp_start):
    """
    These tests verify the module calculates correctly the next scan using
    time intervals greater than one month, one week or one day.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 accum_results=1,
                                                 error_message='Did not receive expected '
                                                               '"Sleeping until ..." event').result()

    next_scan_time_spl = next_scan_time_log.split(" ")
    date = next_scan_time_spl[0].split("/")
    hour = next_scan_time_spl[1].split(":")

    next_scan_time = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(hour[0]), int(hour[1]),
                                       int(hour[2]))

    if tags_to_apply == {'ossec_day_multiple_conf'}:
        if today.month + time_interval <= 12:
            assert next_scan_time.month == today.month + time_interval
        else:
            assert next_scan_time.month == (today.month + time_interval) % 12
    if tags_to_apply == {'ossec_wday_multiple_conf'}:
        assert weekDays[next_scan_time.weekday()] == wday
        assert next_scan_time.day == (today + datetime.timedelta(weeks=time_interval)).day
    if tags_to_apply == {'ossec_time_multiple_conf'}:
        assert next_scan_time.day == (today + datetime.timedelta(days=time_interval)).day
