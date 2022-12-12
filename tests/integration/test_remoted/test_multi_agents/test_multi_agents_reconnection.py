'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


type: integration

brief: 

components:
    - remoted

suite: 

targets:
    - manager

daemons:
    - wazuh-remoted

os_platform:
    - Linux

os_version:
    - Centos 8
    - Ubuntu Focal

references:
    - https://documentation.wazuh.com/current/user-manual/
    - https://documentation.wazuh.com/current/user-manual/

pytest_args:
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - 
'''
import pytest
from pathlib import Path

from wazuh_testing.modules.remoted import CB_KEY_ALREADY_IN_USE
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.file import write_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools.wazuh_manager import wait_agents_active_by_name
from wazuh_testing.tools.virtualization import AgentDockerizer

from . import TESTS_CASES_PATH, CONFIGS_PATH


# Constants
TEST_NAME = Path(__file__).stem.replace('test_', '')
WAIT_AGENTS_START = 30  # Time to wait the agents to start.

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Paths
cases_path = Path(TESTS_CASES_PATH, f'cases_{TEST_NAME}.yml')
config_path = Path(CONFIGS_PATH, f'config_{TEST_NAME}.yml')

# Configurations and test cases
_, metadata, case_ids = get_test_cases_data(cases_path)
configuration = load_configuration_template(config_path, _, metadata)
local_internal_options = {'remoted.debug': '2'}


# Tests
@pytest.mark.parametrize('metadata, configuration', zip(metadata, configuration), ids=case_ids)
def test_remoted_multi_agents(dockerized_agents: AgentDockerizer, metadata: dict,
                              configuration: dict, truncate_monitored_files: None,
                              configure_local_internal_options_module: None,
                              ):
    '''
    description: 
        This test validates the agents reconnect correctly without any race condition
        being raised.

    test_phases:
        - Insert an alert alerts.json file.
        - Replace the alerts.json file while it being read.
        - Check remoted detects the file's inode has changed.
        - Wait for remoted to start reading from the file again.
        - Insert an alert
        - Check virustotal response is added in ossec.log

    wazuh_min_version: 4.4.0

    tier: 1

    parameters:
        - dockerized_agents:
            type: AgentDockerizer
            brief: Running agents inside docker containers.
        - configuration:
            type: dict
            brief: Configuration loaded from `config_path`.
        - metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files before and after the test execution.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart wazuh's daemon before starting a test.
        - wait_for_start_module:
            type: fixture
            brief: Detect the start of the remoted module in the ossec.log

    assertions:
        - Verify all the agents are active after a reconnection

    input_description:
        - The `config_multi_agents_reconnection.yaml` file provides the module configuration for this test.
        - The `cases_multi_agents_reconnection.yaml` file provides the test cases.

    expected_output:
        - Should not match r".*Agent key already in use: agent ID '(\d+)'*."

    '''
    callback = generate_monitoring_callback(CB_KEY_ALREADY_IN_USE)
    hostnames = dockerized_agents.execute('hostname')
    shared_folder = Path(WAZUH_PATH, 'etc', 'shared', 'default')
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)

    # Wait untill the agents are active
    wait_agents_active_by_name(hostnames)
    # Insert a file inside the default group shared folder to restart the agents.
    write_file(Path(shared_folder, 'test.txt'))
    # Verify the agents reconnect and the 'Key already in use' warning is not raised.
    assert wait_agents_active_by_name(hostnames), 'Not all agents reconnected.'
    with pytest.raises(TimeoutError):
        wazuh_monitor.start(callback=callback).result()
