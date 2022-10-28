'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Check if the 'wazuh-syscheckd' daemon is performing a synchronization at the intervals specified in the
       configuration, using the 'interval' tag, if a new synchronization is fired, and the last sync message has been
       recieved in less time than 'response_timeout, the sync interval is doubled.
       The new value for interval cannot be higher than max_interval option. After a new sync interval is tried and the
       last message was recieved in a time that is higher than response_timeout, the sync interval value is returned to
       the configured value.

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
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import TIER1, AGENT, SERVER
from wazuh_testing.modules import fim
from wazuh_testing.fim import callback_detect_synchronization

# Marks
pytestmark = [AGENT, SERVER, TIER1]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_sync_overlap.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_sync_overlap.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = configuration.get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['MONITORED_DIR'] = fim.MONITORED_DIR_1
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
@pytest.mark.parametrize('files_number', [configuration_metadata[0]['files']])
def test_sync_overlap(configuration, metadata, set_wazuh_configuration_fim, create_files_in_folder,
                      restart_syscheck_function, wait_for_fim_start_function):
    '''
    description: Check if the 'wazuh-syscheckd' daemon is performing a synchronization at the interval specified in the
                 configuration, using the 'interval' tag, if a new synchronization is fired, and the last sync message
                 has been recieved in less time than 'response_timeout, the sync interval is doubled.
                 The new value for interval cannot be higher than max_interval option. After a new sync interval is
                 tried and the last message was recieved in a time that is higher than response_timeout, the sync
                 interval value is returned to the configured value.

    test_phases:
        - Create a folder with a number of files inside.
        - Restart syscheckd.
        - Check that a sync interval started.
        - Check that next sync is skipped and interval value is doubled
        - Check that interval value is returned to configured value after successful sync

    wazuh_min_version: 4.5.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration_fim:
            type: fixture
            brief: Set ossec.conf and local_internal_options configuration.
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
        - Verify that the new value for interval when doubled is equal or lower to max_interval.

    input_description: A test case (sync_interval) is contained in external YAML file (cases_sync_overlap.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined with
                       the interval periods and the testing directory to be monitored defined in this module.

    expected_output:
        - r'Initializing FIM Integrity Synchronization check'
        - r"*Sync still in progress. Skipped next sync and increased interval.*'(\\d+)s'"
        - r".*Previous sync was successful. Sync interval is reset to: '(\\d+)s'"

    tags:
        - scheduled
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # If config is invalid, check that invalid config value message appers
    if metadata['response_timeout'] == 'invalid' or metadata['max_interval'] == 'invalid':
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=generate_monitoring_callback(fim.CB_INVALID_CONFIG_VALUE),
                                error_message=fim.ERR_MSG_INVALID_CONFIG_VALUE,
                                update_position=True).result()

    # Wait for new sync
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_synchronization,
                            error_message=fim.ERR_MSG_FIM_SYNC_NOT_DETECTED, update_position=True).result()

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Check if response_timeout has elapsed, and sync is still running, the sync interval is doubled
    interval = wazuh_log_monitor.start(timeout=global_parameters.default_timeout*5,
                                       callback=generate_monitoring_callback(fim.CB_SYNC_SKIPPED),
                                       accum_results=metadata['doubled_times'],
                                       error_message=fim.ERR_MSG_SYNC_SKIPPED_EVENT, update_position=True).result()

    if metadata['doubled_times'] > 1:
        new_interval = interval[-1]
    else:
        new_interval = interval

    # Check interval when doubled is not higher than max interval, if max_interval is higher than configured interval
    # Check interval when doubled is equal than configured interval, if max_interval is lower than configured interval
    if metadata['max_interval'] != 'invalid':
        if not metadata['lower']:
            assert int(new_interval) <= int(metadata['max_interval']), f"Invalid value for interval: {new_interval},\
                                                                         cannot be more than MAX_INTERVAL:\
                                                                         {metadata['max_interval']}"
        else:
            assert int(new_interval) <= int(metadata['interval']), f"Invalid value for interval: {new_interval}, cannot\
                                                                     be more than interval: {metadata['interval']}"

    # Check when sync ends sync_interval is returned to normal after response_timeout since last message.
    if not metadata['lower']:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout*10,
                                callback=generate_monitoring_callback(fim.CB_SYNC_INTERVAL_RESET),
                                error_message=fim.ERR_MSG_SYNC_INTERVAL_RESET_EVENT,
                                update_position=True).result()
