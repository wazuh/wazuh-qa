# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import callback_received_messages_number, publish
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

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

if global_parameters.gcp_topic_name is not None:
    topic_name = global_parameters.gcp_topic_name
else:
    topic_name = 'wazuh-pubsub'
interval = '25s'
pull_on_start = 'no'
max_messages = 100
logging = 'info'
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = True

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

@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
@pytest.mark.parametrize('nmessages', [
    30, 100, 120
])
def test_max_messages(nmessages, get_configuration, configure_environment,
                      restart_wazuh, wait_for_gcp_start):
    """
    Verify the module gcp-pubsub pull a number of messages less than or equal to max_messages. 
    If the number of messages is greater than max_messages, the module will only pull max_messages
    and the rest will be pulled in the next iteration. 
    """
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    # Publish messages to pull them later
    publish(project_id, topic_name, credentials_file, nmessages, "- DEBUG - GCP message")

    if nmessages <= max_messages:
        number_pulled = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval + 5,
                                                callback=callback_received_messages_number,
                                                accum_results=1,
                                                error_message='Did not receive expected '
                                                              '- INFO - Received and acknowledged x messages').result()
        assert int(number_pulled) == nmessages
    else:
        ntimes = int(nmessages / max_messages)
        remainder = int(nmessages % max_messages)

        for i in range(ntimes):
            number_pulled = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval + 5,
                                                    callback=callback_received_messages_number,
                                                    accum_results=1,
                                                    error_message='Did not receive expected '
                                                                  'Received and acknowledged x messages').result()
            assert int(number_pulled) == max_messages
        number_pulled = wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval + 5,
                                                callback=callback_received_messages_number,
                                                accum_results=1,
                                                error_message='Did not receive expected '
                                                              '- INFO - Received and acknowledged x messages').result()
        assert int(number_pulled) == remainder
