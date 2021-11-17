# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
from datetime import timedelta, datetime

from wazuh_testing import global_parameters, logger
from wazuh_testing.tools.time import TimeMachine
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = [pytest.mark.tier(level=0)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_command_conf.yaml')

local_internal_options = {'logcollector.remote_commands': '1', 'logcollector.debug': '2', 'monitord.rotate_log': '0',
                          'windows.debug': '2'}


parameters = [
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo command_5m', 'FREQUENCY': 300},  # 5 minutes.
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo command_30m', 'FREQUENCY': 1800},  # 30 minutes.
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo command_1h', 'FREQUENCY': 3600},  # 1 hour.
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo command_24h', 'FREQUENCY': 86400},  # 24 hours.
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command_5m', 'FREQUENCY': 300},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command_30m', 'FREQUENCY': 1800},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command_1h', 'FREQUENCY': 3600},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo full_command_24h', 'FREQUENCY': 86400}
]
metadata = [
    {'log_format': 'command', 'command': 'echo command_5m', 'frequency': 300, 'freq_str': '5_minutes'},
    {'log_format': 'command', 'command': 'echo command_30m', 'frequency': 1800, 'freq_str': '30_minutes'},
    {'log_format': 'command', 'command': 'echo command_1h', 'frequency': 3600, 'freq_str': '1_hour'},
    {'log_format': 'command', 'command': 'echo command_24h', 'frequency': 86400, 'freq_str': '24_hours'},
    {'log_format': 'full_command', 'command': 'echo full_command_5m', 'frequency': 300, 'freq_str': '5_minutes'},
    {'log_format': 'full_command', 'command': 'echo full_command_30m', 'frequency': 1800, 'freq_str': '30_minutes'},
    {'log_format': 'full_command', 'command': 'echo full_command_1h', 'frequency': 3600, 'freq_str': '1_hour'},
    {'log_format': 'full_command', 'command': 'echo full_command_24h', 'frequency': 86400, 'freq_str': '24_hours'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['log_format']}_{x['freq_str']}" for x in metadata]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_command_execution_freq(configure_local_internal_options_module, get_configuration, file_monitoring,
                                configure_environment, restart_monitord, restart_logcollector):
    """Check if the Wazuh run correctly with the specified command monitoring option "frequency".

    For this purpose, it is verified that the command has not been executed
    before the period established in this option.

    Args:
        configure_local_internal_options_module (fixture): Set internal configuration.
        get_configuration (fixture): Get configurations from the module.
        file_monitoring (fixture): Initialize file to monitor.
        configure_environment (fixture): Configure a custom environment for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
    """
    config = get_configuration['metadata']
    log_callback = logcollector.callback_running_command(log_format=config['log_format'], command=config['command'])

    seconds_to_travel = config['frequency'] / 2  # Middle of the command execution cycle.

    log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    before = str(datetime.now())
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel))
    logger.debug(f"Changing the system clock from {before} to {datetime.now()}")

    # The command should not be executed in the middle of the command execution cycle.
    with pytest.raises(TimeoutError):
        log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                          error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    before = str(datetime.now())
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel))
    logger.debug(f"Changing the system clock from {before} to {datetime.now()}")

    log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                      error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    # Restore the system clock.
    TimeMachine.time_rollback()
