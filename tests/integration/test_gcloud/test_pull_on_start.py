# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

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
interval = '30s'
pull_on_start = ['yes', 'no']
max_messages = 100
logging = "info"
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'INTERVAL': interval,
               'MAX_MESSAGES': max_messages, 'LOGGING': logging, 'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'PULL_ON_START': pull_on_start_value} for pull_on_start_value in pull_on_start),
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
    Verify the module gcp-pubsub starts if pull_on_start is set to yes and 
    the module sleeps if pull_on_start is set to no.
    In the second case, the module will start to pull messages after time interval.  
    """
    pull_start = get_configuration['elements'][0]['pull_on_start']['value'] == 'yes'
    str_interval = get_configuration['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    if pull_start:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_start_fetching_logs,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              '"Starting fetching of logs" event').result()
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_start_gcp_sleep,
                                error_message='Did not receive expected '
                                              '"Sleeping for x seconds" event')
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_start_fetching_logs)
            raise AttributeError(f'Unexpected event {event}')

        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                callback=callback_detect_start_fetching_logs,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              '"Starting fetching of logs" event').result()
