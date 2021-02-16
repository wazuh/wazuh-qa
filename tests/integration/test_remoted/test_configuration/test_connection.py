# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time
import wazuh_testing.api as api
from wazuh_testing.tools import LOG_FILE_PATH

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.monitoring import make_callback, REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_connection.yaml')

parameters = [
    {'CONNECTION': 'secure'},
    {'CONNECTION': 'syslog'},
    {'CONNECTION': 'invalid_option'}
]
metadata = [
    {'connection': 'secure'},
    {'connection': 'syslog'},
    {'connection': 'invalid_option'},
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = ['secure', 'syslog', 'invalid']

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_connection(get_configuration, configure_environment):
    """
    Checks that "connection" option could be configured as "secure" or "syslog" without errors
        this option specifies a type of incoming connection to accept: secure or syslog.

    Checks that the API answer for manager connection coincides with the option selected on ossec.conf
    """

    control_service('restart', daemon='wazuh-remoted')
    truncate_file(LOG_FILE_PATH)

    error_callback = make_callback('ERROR:|CRITICAL:', REMOTED_DETECTOR_PREFIX)

    selected_connection = get_configuration['metadata']['connection']

    if selected_connection == 'invalid_option':
        wazuh_log_monitor.start(timeout=5, callback=error_callback,
                                error_message='remoted started with invalid configuration')
        return

    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=3, callback=error_callback)
        raise SystemError('Error starting remoted with a valid configuration!')

    api_answer_connection = api.get_manager_configuration(section="remote", field="connection")
    assert api_answer_connection == selected_connection
