# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_gcp_alert, validate_gcp_event, publish_sync
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=0), pytest.mark.server]

# variables

interval = '10s'
pull_on_start = 'no'
max_messages = 100
logging = 'debug'
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
file_path = os.path.join(test_data_path, 'gcp_events.txt')

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'LOGGING': logging, 'MODULE_NAME': __name__}

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
def test_rules(get_configuration, configure_environment,
               restart_wazuh, wait_for_gcp_start):
    """
    Verify the module gcp-pubsub pulls messages that matches with GCP rules.
    Alerts are generated and compared with expected rule ID.
    """
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    rules_id = []
    file_ind = 0

    rules_id = [id for id in range(65005, 65011)]
    rules_id += [id for id in range(65012, 65039)]
    rules_id += [id for id in range(65041, 65047)]

    events_file = open(file_path, 'r')
    for line in events_file:
        # Publish messages to pull them later
        publish_sync(global_parameters.gcp_project_id, global_parameters.gcp_topic_name,
                     global_parameters.gcp_credentials_file, [line.strip()])
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                        callback=callback_detect_gcp_alert,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                      'Sending gcp event').result()
        validate_gcp_event(event)
        assert int(event['rule']['id']) == rules_id[file_ind]
        file_ind += 1
    events_file.close()
