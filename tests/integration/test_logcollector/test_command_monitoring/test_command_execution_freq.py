# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
from datetime import timedelta, datetime

from wazuh_testing import logger
from wazuh_testing.tools import get_service, monitoring
from wazuh_testing.tools.time import TimeMachine
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_command_conf.yaml')
wazuh_component = get_service()

if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

local_internal_options = {
    'logcollector.remote_commands': 1,
    'logcollector.debug': 2,
    'monitord.rotate_log': 0
}

parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo execution frequency 300', 'FREQUENCY': 300},  # 5 minutes.
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo execution frequency 1800', 'FREQUENCY': 1800},  # 30 minutes.
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo execution frequency 3600', 'FREQUENCY': 3600},  # 1 hour.
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo execution frequency 86400', 'FREQUENCY': 86400},  # 24 hours.
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command frequency 300', 'FREQUENCY': 300},  # 5 minutes.
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command frequency 1800', 'FREQUENCY': 1800},  # 30 minutes.
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command frequency 3600', 'FREQUENCY': 3600},  # 1 hour.
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command frequency 86400', 'FREQUENCY': 86400}  # 24 hours.
]
metadata = [
    {'log_format': 'command', 'command': 'echo execution frequency 300', 'frequency': 300},  # 5 minutes.
    {'log_format': 'command', 'command': 'echo execution frequency 1800', 'frequency': 1800},  # 30 minutes.
    {'log_format': 'command', 'command': 'echo execution frequency 3600', 'frequency': 3600},  # 1 hour.
    {'log_format': 'command', 'command': 'echo execution frequency 86400', 'frequency': 86400},  # 24 hours.
    {'log_format': 'full_command', 'command': 'echo full_command frequency 300', 'frequency': 300},  # 5 minutes.
    {'log_format': 'full_command', 'command': 'echo full_command frequency 1800', 'frequency': 1800},  # 30 minutes.
    {'log_format': 'full_command', 'command': 'echo full_command frequency 3600', 'frequency': 3600},  # 1 hour.
    {'log_format': 'full_command', 'command': 'echo full_command frequency 86400', 'frequency': 86400}  # 24 hours.
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['COMMAND'], x['FREQUENCY']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


def test_command_execution_freq(get_local_internal_options, configure_local_internal_options, get_configuration,
                                configure_environment, restart_logcollector):
    """Check if the Wazuh run correctly with the specified command monitoring option "frequency".

    For this purpose, it is verified that the command has not been executed
    before the period established in this option.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    cfg = get_configuration['metadata']
    log_format_message = 'full command' if cfg['log_format'] == 'full_command' else 'command'
    msg = fr"DEBUG: Running {log_format_message} '{cfg['command']}'"
    log_callback = monitoring.make_callback(pattern=msg, prefix=prefix)
    seconds_to_travel = cfg['frequency'] / 2  # Middle of the command execution cycle.

    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    before = str(datetime.now())
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel))
    logger.debug(f"Changing the system clock from {before} to {str(datetime.now())}")

    # The command should not be executed in the middle of the command execution cycle.
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    before = str(datetime.now())
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel-5))
    logger.debug(f"Changing the system clock from {before} to {str(datetime.now())}")

    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)
