# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time
import pytest
from google.cloud import pubsub_v1
from google.cloud import storage

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_received_messages_number
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
interval = '30s'
pull_on_start = 'no'
max_messages = 100
logging = 'info'
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

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

def publish(project_id, topic_name, credentials, n):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/var/ossec/{}".format(credentials)

    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project_id, topic_name)

    for n in range(0, n):
        data = u"- DEBUG - Message number {}".format(n)
        # Data must be a bytestring
        data = data.encode("utf-8")
        # Add two attributes, origin and username, to the message
        future = publisher.publish(
            topic_path, data, origin="python-sample", username="gcp"
        )

@pytest.mark.parametrize('nmessages', [
    (30), (100), (120)
])
def test_max_messages(nmessages, get_configuration, configure_environment,
                   restart_wazuh, wait_for_gcp_start):
    """
    Verify the module gcp-pubsub pull a number of messages less than or equal to max_messages. 
    If the number of messages is greater than max_messages, the module will only pull max_messages
    and the rest will be pulled in the next iteration. 
    """
    sinterval = get_configuration['elements'][4]['interval']['value']
    interval = int(''.join(filter(str.isdigit, sinterval)))

    # Publish messages to pull them later
    publish(project_id, topic_name, credentials_file, nmessages)

    if nmessages <= max_messages:
        n = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + interval,
                                    callback=callback_received_messages_number,
                                    accum_results=1,
                                    error_message='Did not receive expected '
                                                  '- INFO - Received and acknowledged x messages').result()
        assert int(n) == nmessages
    else:
        ntimes = int(nmessages / max_messages)
        remainder = int(nmessages % max_messages)

        for i in range(ntimes):
            n = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + interval,
                                        callback=callback_received_messages_number,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                      '- INFO - Received and acknowledged x messages').result()
            assert int(n) == max_messages
        n = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + interval,
                                        callback=callback_received_messages_number,
                                        accum_results=1,
                                        error_message='Did not receive expected '
                                                      '- INFO - Received and acknowledged x messages').result()
        assert int(n) == remainder