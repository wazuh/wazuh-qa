# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_schedule_validate_parameters_err, callback_detect_gcp_read_err
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

project_id = 'sinuous-voice-271711'
subscription_name = 'wazuh-integration'
credentials_file = 'credentials.json'
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

@pytest.mark.parametrize('tags_to_apply', [
    ({'invalid_enabled', 'invalid_pullonstart, invalid_projectid',
      'invalid_subsname', 'invalid_credfile, invalid_maxmessages',
      'invalid_interval', 'invalid_logging, invalid_day',
      'invalid_wday', 'invalid_time', 'invalid_day_wday'})
])
def test_invalid(tags_to_apply, get_configuration, configure_environment, reset_ossec_log):
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
    if tags_to_apply != 'invalid_day_wday':
        line = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_gcp_read_err,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                        'wm_gcp_read(): ERROR:').result()
    else:
        line = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_schedule_validate_parameters_err,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                        'wm_gcp_read(): ERROR:').result()

