# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import datetime

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_start_fetching_logs, callback_detect_start_gcp_sleep
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine
from datetime import timedelta

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
time = now_2m.strftime("%H:%M")

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_schedule_conf.yaml')

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'LOGGING': logging, 'DAY': day, 'WDAY': wday, 'TIME': time,
               'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
                       modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests


def test_schedule_options(get_configuration, configure_environment,
                          restart_wazuh, wait_for_gcp_start):
    """
    These tests verify the module starts to pull according to the day of the week 
    or month and time.
    """
    tags_to_apply = get_configuration['tags'][0]

    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_start_fetching_logs).result()
        raise AttributeError(f'Unexpected event {event}')

    test_today = datetime.date.today()
    if tags_to_apply == 'ossec_day_conf':
        if day <= 28:
            assert day == test_today.day
    if tags_to_apply == 'ossec_wday_conf':
        assert wday == weekDays[test_today.weekday()]

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 120,
                            callback=callback_detect_start_fetching_logs,
                            accum_results=1,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
    seconds_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                                          callback=callback_detect_start_gcp_sleep,
                                          accum_results=1,
                                          error_message='Did not receive expected '
                                                        '"Sleeping for x seconds" event').result()
    seconds = (int(seconds_log)-20)
    TimeMachine.travel_to_future(timedelta(seconds=seconds))
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                            callback=callback_detect_start_fetching_logs,
                            accum_results=1,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
    TimeMachine.travel_to_future(timedelta(seconds=seconds+80-86400), back_in_time=True)
