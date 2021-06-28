# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import pytest
import wazuh_testing.logcollector as logcollector

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH
from wazuh_testing.remote import check_agent_received_message
from wazuh_testing.tools.monitoring import wait_file
from wazuh_testing.tools.file import read_json
from time import sleep

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_macos_file_status_basic.yaml')

parameters = [{'ONLY_FUTURE_EVENTS': 'yes'}, {'ONLY_FUTURE_EVENTS': 'no'}]
metadata = [{'only-future-events': 'yes'}, {'only-future-events': 'no'}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f'{x["ONLY_FUTURE_EVENTS"]}' for x in parameters]

# Time in seconds to update the file_status.json
file_status_update_time = 4

local_internal_options = {'logcollector.vcheck_files': str(file_status_update_time)}


@pytest.fixture(scope='module')
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


def extra_configuration_before_yield():
    """Delete file status file."""
    os.remove(LOGCOLLECTOR_FILE_STATUS_PATH) if os.path.exists(LOGCOLLECTOR_FILE_STATUS_PATH) else None


def test_macos_file_status_basic(get_local_internal_options, configure_local_internal_options, get_configuration,
                                 configure_environment, get_connection_configuration, init_authd_remote_simulator,
                                 restart_logcollector):

    """Checks if logcollector stores correctly "macos"-formatted localfile data.

    This test uses logger tool and a custom log to generate an ULS event. The agent is connected to the authd simulator
    and sends an event to trigger the file_status.json update.

    Raises:
        TimeoutError: If the callbacks, that checks the expected logs, are not satisfied in the expected time.
        FileNotFoundError: If the file_status.json is not available in the expected time.
    """

    macos_message = {
        'command': 'logger',
        'message': 'Logger testing message - file status',
    }

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    wazuh_log_monitor.start(timeout=15, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    # Waits 20 seconds to give time to logcollector to start the module
    sleep(20)

    logcollector.generate_macos_logger_log(macos_message['message'])
    expected_message = logcollector.format_macos_message_pattern(macos_message['command'], macos_message['message'])

    check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_message, timeout=15)

    # Waiting for file_status.json to be created, with a timeout about the time needed to update the file
    wait_file(LOGCOLLECTOR_FILE_STATUS_PATH, file_status_update_time+1)

    # Waits 10 seconds to give time to logcollector to update the file_status.json file
    sleep(10)

    file_status_json = read_json(LOGCOLLECTOR_FILE_STATUS_PATH)

    conf_predicate = get_configuration['sections'][0]['elements'][2]['query']['value']
    conf_level = get_configuration['sections'][0]['elements'][2]['query']['attributes'][0]['level']
    conf_type = get_configuration['sections'][0]['elements'][2]['query']['attributes'][1]['type']

    # Check if json has a structure
    assert file_status_json['macos'], 'Error finding "macos" key'

    assert file_status_json['macos']['timestamp'], 'Error finding "timestamp" key inside "macos"'

    assert re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}-\d{4}$',
                    file_status_json['macos']['timestamp']), \
        'Error of timestamp format'

    assert file_status_json['macos']['settings'], 'Error finding "settings" key inside "macos"'

    assert file_status_json['macos']['settings'] \
        == logcollector.compose_macos_log_command(conf_type,
                                                  conf_level,
                                                  conf_predicate)
