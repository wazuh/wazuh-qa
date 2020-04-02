# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_start_fetching_logs, callback_detect_start_gcp_sleep
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

project_id = 'sinuous-voice-271711'
subscription_name = 'wazuh-integration'
credentials_file = 'credentials.json'
interval = ['30s', '1m']
pull_on_start = 'yes'
max_messages = 100
logging = "info"
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'PULL_ON_START': pull_on_start,
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

def test_pull_on_start(get_configuration, configure_environment,
                       restart_wazuh, wait_for_gcp_start):
    """
    These tests verify the module starts to pull after the time interval
    that has to match the value of the 'interval' parameter.
    """
    str_interval = get_configuration['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    if 'm' in str_interval:
        time_interval *= 60
    seconds_log = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=callback_detect_start_gcp_sleep,
                                          accum_results=1,
                                          error_message='Did not receive expected '
                                                        '"Sleeping for x seconds" event').result()
    start_time = time.time()

    assert time_interval - int(seconds_log) <= 10

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                            callback=callback_detect_start_fetching_logs,
                            accum_results=1,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event').result()
    end_time = time.time()
    diff_time = int(end_time - start_time)
    assert time_interval - diff_time <= 10
