# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import os
import sys
from datetime import timedelta

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

if global_parameters.gcp_project_id is not None:
    project_id = global_parameters.gcp_project_id
else:
    raise ValueError(f"Google Cloud project id not found. Please use --gcp-project-id")

if global_parameters.gcp_subscription_name is not None:
    subscription_name = global_parameters.gcp_subscription_name
else:
    raise ValueError(f"Google Cloud subscription name not found. Please use --gcp-subscription-name")

if global_parameters.gcp_credentials_file is not None:
    credentials_file = global_parameters.gcp_credentials_file
else:
    raise ValueError(f"Credentials json file not found. Please enter a valid path using --gcp-credentials-file")
interval = '1h'
pull_on_start = 'no'
max_messages = 100
logging = "info"

today = datetime.date.today()
day = today.day

weekDays = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
wday = weekDays[today.weekday()]

now = datetime.datetime.now()
now_2m = now + datetime.timedelta(minutes=2, seconds=00)
now_4m = now + datetime.timedelta(minutes=4, seconds=00)
now_6m = now + datetime.timedelta(minutes=6, seconds=00)
day_time = now_2m.strftime("%H:%M")
wday_time = now_4m.strftime("%H:%M")
time = now_6m.strftime("%H:%M")

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_schedule_conf.yaml')
force_restart_after_restoring = True

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'LOGGING': logging, 'DAY': day, 'WDAY': wday, 'DAY_TIME': day_time,
               'WDAY_TIME': wday_time, 'TIME': time, 'MODULE_NAME': __name__}

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
    check_apply_test(tags_to_apply, get_configuration['tags'])

    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=3,
                                        callback=callback_detect_start_fetching_logs).result()
        raise AttributeError(f'Unexpected event {event}')

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 120,
                            callback=callback_detect_start_fetching_logs,
                            accum_results=1,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 accum_results=1,
                                                 error_message='Did not receive expected '
                                                               '"Sleeping until ..." event').result()
    next_scan_time_spl = next_scan_time_log.split(" ")
    date = next_scan_time_spl[0].split("/")
    hour = next_scan_time_spl[1].split(":")

    test_now = datetime.datetime.now()
    next_scan_time = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(hour[0]), int(hour[1]),
                                       int(hour[2]))
    diff_time = (next_scan_time - test_now).total_seconds()
    seconds = (int(diff_time - 20))

    TimeMachine.travel_to_future(timedelta(seconds=seconds))

    test_today = datetime.date.today()
    if tags_to_apply == {'ossec_day_conf'}:
        if today.month < 12:
            assert test_today.month == today.month + 1
        else:
            assert test_today.month == 1
    if tags_to_apply == {'ossec_wday_conf'}:
        assert weekDays[test_today.weekday()] == wday
        assert test_today.day == (today + datetime.timedelta(weeks=1)).day
    if tags_to_apply == {'ossec_time_conf'}:
        assert test_today.day == (today + datetime.timedelta(days=1)).day

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                            callback=callback_detect_start_fetching_logs,
                            accum_results=1,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
    TimeMachine.travel_to_future(timedelta(seconds=seconds + 20 - 172800), back_in_time=True)


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

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 120,
                            callback=callback_detect_start_fetching_logs,
                            accum_results=1,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
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
