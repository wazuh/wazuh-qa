# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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
force_restart_after_restoring = True

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'PULL_ON_START': pull_on_start,
               'MAX_MESSAGES': max_messages, 'LOGGING': logging, 'MODULE_NAME': __name__}

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
def test_interval(get_configuration, configure_environment,
                  restart_wazuh, wait_for_gcp_start):
    """
    These tests verify the module starts to pull after the time interval
    that has to match the value of the 'interval' parameter.
    """
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    if 'm' in str_interval:
        time_interval *= 60

    start_time = time.time()
    next_scan_time_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + 60,
                                                 callback=callback_detect_start_gcp_sleep,
                                                 accum_results=1,
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
                            accum_results=1,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
    end_time = time.time()
    diff_time = int(end_time - start_time)
    assert time_interval - diff_time <= 10
