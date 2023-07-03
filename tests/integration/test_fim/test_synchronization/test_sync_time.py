'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Check when the 'wazuh-syscheckd' daemon is performing a synchronization, a normal synchronization will end
before the configured `interval` and `max_interval`.

components:
    - fim

suite: synchronization

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows Server 2019


references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        scheduled: monitoring is done at a preconfigured interval.
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Basic functionalities and quick to perform.
        1: Functionalities of medium complexity.
        2: Advanced functionalities and are slow to perform.

tags:
    - fim_synchronization
'''
import os
import pytest


from wazuh_testing import global_parameters
from wazuh_testing.tools import LOG_FILE_PATH, configuration
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules import TIER1, AGENT, SERVER
from wazuh_testing.modules.fim import MONITORED_DIR_1, FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.modules.fim import event_monitor as evm

# Marks
pytestmark = [AGENT, SERVER, TIER1]

local_internal_options = FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_sync_time.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_sync_time.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = configuration.get_test_cases_data(test_cases_path)
# This assigns the monitored_dir during runtime depending on the OS, cannot be added to yaml
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['MONITORED_DIR'] = MONITORED_DIR_1
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_sync_time(configuration, metadata, set_wazuh_configuration, configure_local_internal_options_function,
                   create_files_in_folder, restart_syscheck_function, wait_fim_start):
    '''
    description: Check when the 'wazuh-syscheckd' daemon is performing a synchronization, a normal synchronization
                 will end before the configured `interval` and `max_interval`.

    test_phases:
        - Create a folder with a number of files inside.
        - Restart syscheckd.
        - Check that a sync interval started, and get the time it starts
        - Get all the integrity state events time.
        - Assert that the time it took for the sync to complete was less than the configured interval and max_interval.

    wazuh_min_version: 4.6.0

    tier: 2

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options.conf file.
        - create_files_in_folder:
            type: fixture
            brief: create files in monitored folder, and delete them after the test.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.
        - wait_for_fim_start_function:
            type: fixture
            brief: check that the starting fim scan is detected.

    assertions:
        - Assert sync time delta is smaller than interval
        - Assert sync time delta is smaller than max_interval

    input_description: A test case is contained in external YAML file (cases_sync_interval.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon. That is combined with the interval
                       periods and the testing directory to be monitored defined in this module.

    expected_output:
        - r'Initializing FIM Integrity Synchronization check'
        - r".*Executing FIM sync"
        - r".*Sending integrity control message.*"

    tags:
        - scheduled
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Wait for new sync and get start time
    sync_time = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=evm.callback_sync_start_time,
                                        error_message=evm.ERR_MSG_FIM_SYNC_NOT_DETECTED, update_position=True).result()

    # Get the time of all the sync state events for the created files
    results = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                      callback=evm.callback_state_event_time, accum_results=3,
                                      error_message=evm.ERR_MSG_FIM_SYNC_NOT_DETECTED, update_position=True).result()

    # Calculate timedelta between start of sync and last message.
    # Add 1 second to take into account the first second from the scan
    delta = (results[-1] - sync_time).total_seconds() + 1

    # Assert that sync took less time that interval and max_interval
    assert delta <= metadata['interval'], f"Error: Sync took longer than interval: {metadata['interval']}"
    assert delta <= metadata['max_interval'], f"Error: Sync took longer than max_interval: {metadata['max_interval']}"
