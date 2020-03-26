# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time
import pytest
from google.cloud import pubsub_v1
from google.cloud import storage

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_detect_all_gcp
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
interval = '20s'
pull_on_start = 'yes'
max_messages = 100
logging = ['info', 'debug', 'warning', 'error', 'critical']
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'INTERVAL': interval,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'LOGGING': logging_value} for  logging_value in logging),
                       modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def publish(project_id, topic_name, credentials, n=5):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/var/ossec/{}".format(credentials)

    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project_id, topic_name)

    for n in range(0, n):
        data = u"Message number {}".format(n)
        # Data must be a bytestring
        data = data.encode("utf-8")
        # Add two attributes, origin and username, to the message
        future = publisher.publish(
            topic_path, data, origin="python-sample", username="gcp"
        )

def test_logging(get_configuration, configure_environment,
                 restart_wazuh, wait_for_gcp_start):
    """
    When a logging option is used, it cannot be an event that has another logging option.
    For example, events from gcp-pubusb will only have '- INFO -' if logging = info.
    """
    sinterval = get_configuration['elements'][4]['interval']['value']
    logging_opt = get_configuration['elements'][6]['logging']['value']
    interval = int(''.join(filter(str.isdigit, sinterval)))

    if logging_opt == 'info':
        filt = ['- DEBUG -', '- WARNING -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'debug':
        filt = ['- INFO -', '- WARNING -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'warning':
        filt = ['- INFO -', '- DEBUG -', '- ERROR -', '- CRITICAL -']
    elif logging_opt == 'warning':
        filt = ['- INFO -', '- DEBUG -', '- WARNING -', '- CRITICAL -']
    else:
        filt = ['- INFO -', '- DEBUG -', '- WARNING -', '- ERROR -']

    # Publish messages to pull them later
    publish(project_id, topic_name, credentials_file)
    
    found = 0
    for i in range (0,12):
        n = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + interval + 5,
                                    callback=callback_detect_all_gcp,
                                    accum_results=1,
                                    error_message='Did not receive expected '
                                                  'wazuh-modulesd:gcp-pubsub[]').result()
        for j in filt:
            if j in n:
                found = 1
    assert found == 0