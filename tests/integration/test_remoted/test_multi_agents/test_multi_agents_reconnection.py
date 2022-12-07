'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


type: integration

brief: Integratord manages wazuh integrations with other applications such as Yara or Virustotal, by feeding
the integrated aplications with the alerts located in alerts.json file. This test module aims to validate that
given a specific alert, the expected response is recieved, depending if it is a valid/invalid json alert, an
overlong alert (64kb+) or what happens when it cannot read the file because it is missing.

components:
    - integratord

suite: integratord_change_inode_alert

targets:
    - agent

daemons:
    - wazuh-integratord

os_platform:
    - Linux

os_version:
    - Centos 8
    - Ubuntu Focal

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/virustotal-scan/integration.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.htm

pytest_args:
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - virustotal
'''
import os
import time
import pytest
import socket
import re

import wazuh_testing.tools.configuration as conf

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH, ALERT_FILE_PATH
from wazuh_testing.tools.file import remove_file, copy
from wazuh_testing.tools.configuration import (
    get_test_cases_data,
    load_configuration_template,
)
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback


# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Local Internal
local_internal_options = {'remoted.debug': '2'}

# Reference paths
TEST_NAME = 'multi_agents_reconnection'
DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIG_TEMPS_PATH = os.path.join(DATA_PATH, 'config_templates')
TESTS_CASES_PATH = os.path.join(DATA_PATH, 'test_cases')

# Configuration and cases data
configs_path = os.path.join(CONFIG_TEMPS_PATH, 'config_{TEST_NAME}.yml')
cases_path = os.path.join(TESTS_CASES_PATH, 'cases_{TEST_NAME}.yml')

# Configurations
# configs_params, metadata, case_ids = get_test_cases_data(cases_path)
# configurations = load_configuration_template(configs_path, configs_params,
#                                              metadata)

# Variables
# TEMP_FILE_PATH = os.path.join(WAZUH_PATH, 'logs/alerts/alerts.json.tmp')
AGENT_CONFIG_PATH = os.path.join(DATA_PATH, 'ossec.conf')

# AGENTS OSSEC.CONF


@pytest.fixture
def set_agents_configuration():
    '''Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf
    '''
    # Save current configuration
    with open(AGENT_CONFIG_PATH) as f:
        backup_config = f.read()
    # Configuration for testing
    test_config = set_ip_to_agent_config(backup_config)
    # Set new configuration
    write_file(AGENT_CONFIG_PATH, test_config)
    yield
    # Restore previous configuration
    write_file(AGENT_CONFIG_PATH, backup_config)


def write_file(file: str, data: str):
    with open(file, 'w') as f:
        f.writelines(data)


def set_ip_to_agent_config(config: str):
    reg = '(?<=%s).*?(?=%s)' % ('<address>', '</address>')
    r = re.compile(reg, re.DOTALL)
    return r.sub(get_ip_address(), config)


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    return s.getsockname()[0]


# Tests
# @pytest.mark.parametrize('configuration, metadata', zip(configurations, metadata), ids=case_ids)
def test_integratord_change_json_inode(
    set_agents_configuration,
    # configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
    #                                    configure_local_internal_options_module, restart_wazuh_daemon_function,
    #                                    wait_for_start_module
):
    '''
    description: Check that if when reading the alerts.json file, the inode for the file changes, integratord will
                 reload the file and continue reading from it.

    test_phases:
        - Insert an alert alerts.json file.
        - Replace the alerts.json file while it being read.
        - Check integratord detects the file's inode has changed.
        - Wait for integratord to start reading from the file again.
        - Insert an alert
        - Check virustotal response is added in ossec.log

    wazuh_min_version: 4.3.7

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart wazuh's daemon before starting a test.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `config_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_json_alerts` file provides the test cases.

    expected_output:
        - r'.*(wazuh-integratord.*DEBUG: jqueue_next.*Alert file inode changed).*'

    '''
    # wazuh_monitor = FileMonitor(LOG_FILE_PATH)

    # # Monitor Inode Changed
    # check_integratord_event(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout * 2,
    #                         callback=generate_monitoring_callback(integrator.CB_ALERTS_FILE_INODE_CHANGED),
    #                         error_message=integrator.ERR_MSG_ALERT_INODE_CHANGED_NOT_FOUND)

    # # Read Response in ossec.log
    # check_integratord_event(file_monitor=wazuh_monitor, timeout=global_parameters.default_timeout,
    #                         callback=generate_monitoring_callback(integrator.CB_PROCESSING_ALERT),
    #                         error_message=integrator.ERR_MSG_VIRUSTOTAL_ALERT_NOT_DETECTED)
    print(get_ip_address())
