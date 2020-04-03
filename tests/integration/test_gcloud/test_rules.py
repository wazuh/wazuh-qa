# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
from google.cloud import pubsub_v1

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_gcp_alert, validate_gcp_event
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

project_id = 'sinuous-voice-271711'
subscription_name = 'wazuh-integration'
topic_name = 'wazuh-pubsub'
credentials_file = 'credentials.json'
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
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'INTERVAL': interval,
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

def publish(id_project, name_topic, credentials, repetitions=1, msg=None):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/var/ossec/{}".format(credentials)

    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(id_project, name_topic)

    for number in range(repetitions):
        data = u"{}".format(msg)
        # Data must be a bytestring
        data = data.encode("utf-8")
        # Add two attributes, origin and username, to the message
        future = publisher.publish(
            topic_path, data, origin="python-sample", username="gcp"
        )


def test_rules(get_configuration, configure_environment,
               restart_wazuh, wait_for_gcp_start):
    """
    Verify the module gcp-pubsub pulls messages that matches with GCP rules.
    Alerts are generated and compared with expected rule ID.
    """
    str_interval = get_configuration['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))
    rules_id = []
    file_ind = 0

    for number in range(65004, 65037):
        rules_id.append(number)

    for number in range(65039, 65045):
        rules_id.append(number)

    events_file = open(file_path, 'r')
    for line in events_file:
        # Publish messages to pull them later
        publish(project_id, topic_name, credentials_file, 1, line)
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                                        callback=callback_detect_gcp_alert,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                      'Sending gcp event').result()
        validate_gcp_event(event)
        assert int(event['rule']['id']) == rules_id[file_ind]
        file_ind += 1
    events_file.close()
