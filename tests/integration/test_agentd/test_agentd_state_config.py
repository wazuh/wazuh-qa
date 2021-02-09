# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import yaml
import sys
import time

from wazuh_testing import global_parameters
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.agent import (callback_state_interval_not_valid,
                                 callback_state_interval_not_found,
                                 callback_state_file_enabled,
                                 callback_state_file_not_enabled)
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.fim import (change_internal_options)
from wazuh_testing.tools.services import (control_service,
                                          check_if_process_is_running)

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0),
              pytest.mark.agent]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
test_data_file = os.path.join(test_data_path, 'wazuh_state_config_tests.yaml')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)

# Open test cases description file
with open(test_data_file) as f:
    test_cases = yaml.safe_load(f)

# Variables
if sys.platform == 'win32':
    state_file_path = os.path.join(WAZUH_PATH, 'wazuh-agent.state')
    internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')
else:
    state_file_path = os.path.join(WAZUH_PATH, 'var', 'run',
                                   'wazuh-agentd.state')
    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

# ossec.log watch callbacks
callbacks = {
    "interval_not_valid": callback_state_interval_not_valid,
    "interval_not_found": callback_state_interval_not_found,
    "file_enabled": callback_state_file_enabled,
    "file_not_enabled": callback_state_file_not_enabled
}


# Functions
def control_service_unconditionally(action, daemon=None):
    """Control services avoiding handling exception

    Parameters
    ----------
        action : {'stop', 'start', 'restart'}
            Action to be done with the service/daemon.
        daemon : str, optional
            Name of the daemon to be controlled.
                None to control the whole Wazuh service. Default `None`.
    """
    try:
        control_service(action, daemon=daemon)
    except Exception:
        pass


def extra_configuration_before_yield():
    change_internal_options('agent.debug', '2')


def extra_configuration_after_yield():
    # Set default values
    change_internal_options('agent.debug', '0')
    set_state_interval(5)


def set_state_interval(interval):
    """Set agent.state_interval value on internal_options.conf
    Args:
        interval:
            - Different than `None`: set agent.state_interval
                                     value on internal_options.conf
            - `None`: agent.state_interval will be removed
                      from internal_options.conf
    """
    if interval is not None:
        change_internal_options('agent.state_interval', interval,
                                opt_path=internal_options)
    else:
        new_content = ''
        with open(internal_options) as f:
            lines = f.readlines()

        for line in lines:
            new_line = line if 'agent.state_interval' not in line else ''
            new_content += new_line

        with open(internal_options, 'w') as f:
            f.write(new_content)


def files_setup():
    """Truncate ossec.log and remote state file"""
    truncate_file(LOG_FILE_PATH)
    os.remove(state_file_path) if os.path.exists(state_file_path) else None


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_agentd_state_config(configure_environment, test_case: list):

    control_service_unconditionally('stop', 'wazuh-agentd')

    files_setup()
    set_state_interval(test_case['interval'])

    control_service_unconditionally('start', 'wazuh-agentd')

    # Check if test require checking state file existance
    if 'state_file_exist' in test_case:
        if test_case['state_file_exist'] is True:
            # Wait until state file was dumped
            time.sleep(test_case['interval'])
        assert test_case['state_file_exist'] == os.path.exists(state_file_path)

    # Follow ossec.log to find desired messages by a callback
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callbacks.get(test_case['log_expect']),
                            error_message='Event not found')
    assert wazuh_log_monitor.result()

    # Check if test require checking agentd status
    if 'agentd_ends' in test_case:
        assert (test_case['agentd_ends']
                is not check_if_process_is_running('wazuh-agentd'))
