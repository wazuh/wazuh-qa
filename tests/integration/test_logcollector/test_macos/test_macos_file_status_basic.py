# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import json
import re

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.remote import check_agent_received_message
from wazuh_testing.tools import WAZUH_PATH

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_file_status_basic.yaml')
parameters = [{'ONLY_FUTURE_EVENTS': 'yes'}, {'ONLY_FUTURE_EVENTS': 'no'}]
metadata = [{'only-future-events': 'yes'}, {'only-future-events': 'no'}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['ONLY_FUTURE_EVENTS']}" for x in parameters]


file_status_path = os.path.join(WAZUH_PATH, 'queue', 'logcollector', 'file_status.json')

# configurations = load_wazuh_configurations(configurations_path, __name__)

macos_log_messages = [
    {
        'command': 'logger',
        'message': "Logger testing message - file status",
    }
]


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param



@pytest.fixture(scope="module")
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


@pytest.mark.parametrize('macos_message', macos_log_messages)
def test_macos_file_status_basic(get_configuration, configure_environment, get_connection_configuration,
                            init_authd_remote_simulator, macos_message, restart_logcollector):

    """Check if logcollector gather correctly macOS unified logging system events.

    This test uses logger tool and a custom log to generate ULS events. The agent is connected to a authd simulator
    and sended events are gather using remoted simulator tool.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """

    # Remove status file to check if agent behavior is as expected
    os.remove(file_status_path) if os.path.exists(file_status_path) else None

    expected_macos_message = ""
    log_command = macos_message['command']

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    wazuh_log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    logcollector.generate_macos_logger_log(macos_message['message'])
    expected_macos_message = logcollector.format_macos_message_pattern(macos_message['command'], 
                                                                       macos_message['message'])

    check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_macos_message, timeout=40)

    file_status_json = ""

    try:
        with open(file_status_path) as json_status:
            file_status_json = json.loads(json_status.read())
    except EnvironmentError:
        assert False, "Error opening '{}'".format(file_status_path)

    # Check if json has a structure
    assert file_status_json["macos"], "Error finding 'macos' key"
    assert file_status_json["macos"]["timestamp"], "Error finding 'timestamp' key inside 'macos'"
    assert re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}-\d{4}$', file_status_json["macos"]["timestamp"]), "Error of timestamp format"
    assert file_status_json["macos"]["settings"], "Error finding 'settings' key inside 'macos'"

