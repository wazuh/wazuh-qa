# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_schedule_validate_parameters_err, callback_detect_gcp_read_err, \
    callback_detect_gcp_wmodule_err, callback_detect_schedule_read_err
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

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
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'invalid_conf.yaml')
force_restart_after_restoring = True

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_invalid(get_configuration, configure_environment, reset_ossec_log):
    """
    Checks if an invalid configuration is detected

    Using invalid configurations with different attributes, 
    expect an error message and gcp-pubsub unable to start.
    """
    # Configuration error -> ValueError raised
    try:
        control_service('restart')
    except ValueError:
        assert sys.platform != 'win32', 'Restarting ossec with invalid configuration should ' \
                                        'not raise an exception in win32'
    tags_to_apply = get_configuration['tags'][0]

    if tags_to_apply == 'invalid_gcp_wmodule':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_gcp_wmodule_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'Invalid element in the configuration').result()
    elif tags_to_apply == 'invalid_day_wday':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_schedule_validate_parameters_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    elif tags_to_apply == 'invalid_schedule':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_schedule_read_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'sched_scan_validate_parameters(): ERROR').result()
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_detect_gcp_read_err,
                                accum_results=1,
                                error_message='Did not receive expected '
                                              'wm_gcp_read(): ERROR:').result()
