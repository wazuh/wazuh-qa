# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_schedule_validate_parameters_warn
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

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
interval = ['1d', '1w', '1M']
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'schedule_conf.yaml')
force_restart_after_restoring = True

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'MODULE_NAME': __name__}
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
def test_schedule(get_configuration, configure_environment, restart_wazuh):
    """
    When day option is used, interval has to be a multiple of one month.
    When wday option is used, interval has to be a multiple of one week.
    When time option is used, interval has to be a multiple of one week or day.
    """
    str_interval = get_configuration['sections'][0]['elements'][3]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    tags_to_apply = get_configuration['tags'][0]

    if tags_to_apply == 'schedule_day':
        if 'M' not in str_interval:
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                    callback=callback_detect_schedule_validate_parameters_warn,
                                    accum_results=2,
                                    error_message='Did not receive expected '
                                                  'at _sched_scan_validate_parameters(): WARNING:').result()
        else:
            with pytest.raises(TimeoutError):
                event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                callback=callback_detect_schedule_validate_parameters_warn).result()
                raise AttributeError(f'Unexpected event {event}')

    elif tags_to_apply == 'schedule_wday':
        if 'w' not in str_interval:
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                    callback=callback_detect_schedule_validate_parameters_warn,
                                    accum_results=2,
                                    error_message='Did not receive expected '
                                                  'at _sched_scan_validate_parameters(): WARNING:').result()
        else:
            with pytest.raises(TimeoutError):
                event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                callback=callback_detect_schedule_validate_parameters_warn).result()
                raise AttributeError(f'Unexpected event {event}')
    else:
        if 'd' not in str_interval and 'w' not in str_interval:
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                    callback=callback_detect_schedule_validate_parameters_warn,
                                    accum_results=2,
                                    error_message='Did not receive expected '
                                                  'at _sched_scan_validate_parameters(): WARNING:').result()
        else:
            with pytest.raises(TimeoutError):
                event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                callback=callback_detect_schedule_validate_parameters_warn).result()
                raise AttributeError(f'Unexpected event {event}')
