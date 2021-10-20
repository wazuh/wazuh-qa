# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_all_gcp
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = '25s'
pull_on_start = 'yes'
max_messages = 100
logging = ['info', 'debug', 'warning', 'error', 'critical']
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = True

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'LOGGING': logging_value} for logging_value in logging),
                       modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
@pytest.mark.parametrize('publish_messages', [
    ['- DEBUG - GCP message' for _ in range(5)]
], indirect=True)
def test_logging(get_configuration, configure_environment, publish_messages,
                 restart_wazuh, wait_for_gcp_start):
    """
    When a logging option is used, it cannot be an event that has another logging option.
    For example, events from gcp-pubusb will only have '- INFO -' if logging = info.
    """
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    logging_opt = get_configuration['sections'][0]['elements'][6]['logging']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    if logging_opt == 'info':
        key_words = ['- DEBUG -', '- WARNING -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'debug':
        key_words = ['- INFO -', '- WARNING -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'warning':
        key_words = ['- INFO -', '- DEBUG -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'warning':
        key_words = ['- INFO -', '- DEBUG -', '- WARNING -', '- CRITICAL -']
    else:
        key_words = ['- INFO -', '- DEBUG -', '- WARNING -', '- ERROR -']

    for nevents in range(0, 12):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval + 5,
                                        callback=callback_detect_all_gcp,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                      'wazuh-modulesd:gcp-pubsub[]').result()

        for key in key_words:
            assert key not in event
