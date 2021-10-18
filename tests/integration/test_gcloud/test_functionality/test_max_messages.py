# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.gcloud import callback_detect_start_fetching_logs, callback_received_messages_number
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from google.cloud import pubsub_v1

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

interval = '25s'
pull_messages_timeout = global_parameters.default_timeout + 60
pull_on_start = 'no'
max_messages = 100
logging = 'info'
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
@pytest.mark.skip(reason="It will be blocked by #1906 on 4.2, when it will solve on 4.3 we can enable again this test.")
# @pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
@pytest.mark.parametrize('publish_messages', [
    ['- DEBUG - GCP message' for _ in range(30)],
    ['- DEBUG - GCP message' for _ in range(100)],
    ['- DEBUG - GCP message' for _ in range(120)]
], indirect=True)
def test_max_messages(get_configuration, configure_environment, publish_messages,
                      restart_wazuh, wait_for_gcp_start):
    """
    Verify the module gcp-pubsub pull a number of messages less than or equal to max_messages.
    If the number of messages is greater than max_messages, the module will only pull max_messages
    and the rest will be pulled in the next iteration.
    """
    str_interval = get_configuration['sections'][0]['elements'][4]['interval']['value']
    time_interval = int(''.join(filter(str.isdigit, str_interval)))

    # Wait till the fetch starts
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout + time_interval,
                            callback=callback_detect_start_fetching_logs,
                            error_message='Did not receive expected '
                                          '"Starting fetching of logs" event')

    if publish_messages <= max_messages:
        number_pulled = wazuh_log_monitor.start(timeout=pull_messages_timeout,
                                                callback=callback_received_messages_number,
                                                error_message='Did not receive expected '
                                                              '- INFO - Received and acknowledged x messages').result()
        # GCP might log messages from sources other than ourselves
        assert int(number_pulled) >= publish_messages
    else:
        ntimes = int(publish_messages / max_messages)
        remainder = int(publish_messages % max_messages)

        for i in range(ntimes):
            number_pulled = wazuh_log_monitor.start(timeout=pull_messages_timeout,
                                                    callback=callback_received_messages_number,
                                                    error_message='Did not receive expected '
                                                                  'Received and acknowledged x messages').result()
            assert int(number_pulled) == max_messages
        number_pulled = wazuh_log_monitor.start(timeout=pull_messages_timeout,
                                                callback=callback_received_messages_number,
                                                error_message='Did not receive expected '
                                                              '- INFO - Received and acknowledged x messages').result()
        # GCP might log messages from sources other than ourselves
        assert int(number_pulled) >= remainder
