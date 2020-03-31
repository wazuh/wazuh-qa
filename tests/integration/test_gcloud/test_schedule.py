# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_schedule_validate_parameters_warn
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

project_id = 'sinuous-voice-271711'
subscription_name = 'wazuh-integration'
credentials_file = 'credentials.json'
interval = ['1d', '1w', '1M']
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'schedule_conf.yaml')

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'INTERVAL': interval_value} for  interval_value in interval),
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

def test_schedule_day(get_configuration, configure_environment, restart_wazuh):
    """
    When day option is used, interval has to be a multiple of one month.
    """
    check_apply_test({'schedule_day'}, get_configuration['tags'])
    sinterval = get_configuration['elements'][3]['interval']['value']
    interval = int(''.join(filter(str.isdigit, sinterval)))

    if 'M' not in sinterval:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + interval,
                                callback=callback_detect_schedule_validate_parameters_warn,
                                accum_results=2,
                                error_message='Did not receive expected '
                                              'at _sched_scan_validate_parameters(): WARNING:').result()
    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_schedule_validate_parameters_warn).result()
            raise AttributeError(f'Unexpected event {event}')

def test_schedule_wday(get_configuration, configure_environment, restart_wazuh):
    """
    When wday option is used, interval has to be a multiple of one week.
    """
    check_apply_test({'schedule_wday'}, get_configuration['tags'])
    sinterval = get_configuration['elements'][3]['interval']['value']
    interval = int(''.join(filter(str.isdigit, sinterval)))

    if 'w' not in sinterval:
        line = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + interval,
                                callback=callback_detect_schedule_validate_parameters_warn,
                                accum_results=2,
                                error_message='Did not receive expected '
                                              'at _sched_scan_validate_parameters(): WARNING:').result()
    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_schedule_validate_parameters_warn).result()
            raise AttributeError(f'Unexpected event {event}')

def test_schedule_time(get_configuration, configure_environment, restart_wazuh):
    """
    When time option is used, interval has to be a multiple of one week or day.
    """
    check_apply_test({'schedule_time'}, get_configuration['tags'])
    sinterval = get_configuration['elements'][3]['interval']['value']
    interval = int(''.join(filter(str.isdigit, sinterval)))

    if 'd' not in sinterval and 'w' not in sinterval:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + interval,
                                callback=callback_detect_schedule_validate_parameters_warn,
                                accum_results=2,
                                error_message='Did not receive expected '
                                              'at _sched_scan_validate_parameters(): WARNING:').result()
    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_schedule_validate_parameters_warn).result()
            raise AttributeError(f'Unexpected event {event}')
