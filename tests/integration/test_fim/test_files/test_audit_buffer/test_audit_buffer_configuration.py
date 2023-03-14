'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files are
       added, modified or deleted. It can monitor using Audit information (whodata mode). Whodata mode has an option
       'queue_size' that will save whodata events up until it is full so it can decode them and generate alerts. Events
       in excess of the queue will be dropped and handled in the next scheduled scan. This is done to avoid blocking
       the audit socket.

components:
    - fim

suite: audit_buffer

targets:
    - manager
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - linux

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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html

pytest_args:
    - fim_mode:
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - windows_folder_redirection
'''
import os


import pytest
from wazuh_testing import LOG_FILE_PATH, T_5
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim import TEST_DIR_1, AUDIT_QUEUE_SIZE_DEFAULT_VALUE
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (get_configured_whodata_queue_size, detect_audit_queue_full,
                                                     detect_invalid_conf_value, detect_audit_healthcheck_failed,
                                                     detect_whodata_start)


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables
test_folders = [os.path.join(PREFIX, TEST_DIR_1)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# ---------------------------------------TEST_AUDIT_BUFFER_DEFAULT-------------------------------------------
# Configuration and cases data
t1_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_audit_buffer_default.yaml')
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_audit_buffer_default.yaml')

# Test configurations
t1_configuration_parameters, t1_configuration_metadata, t1_test_case_ids = get_test_cases_data(t1_test_cases_path)
for count, value in enumerate(t1_configuration_parameters):
    t1_configuration_parameters[count]['TEST_DIRECTORIES'] = test_folders[0]
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ---------------------------------------TEST_AUDIT_BUFFER_VALUES-------------------------------------------
# Configuration and cases data
t2_test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_audit_buffer_values.yaml')
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_audit_buffer_values.yaml')

# Test configurations
t2_configuration_parameters, t2_configuration_metadata, t2_test_case_ids = get_test_cases_data(t2_test_cases_path)
for count, value in enumerate(t2_configuration_parameters):
    t2_configuration_parameters[count]['TEST_DIRECTORIES'] = test_folders[0]
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)


# Tests
@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata),
                         ids=t1_test_case_ids)
def test_audit_buffer_default(configuration, metadata, test_folders, set_wazuh_configuration,
                              create_monitored_folders_module, configure_local_internal_options_function,
                              restart_syscheck_function):
    '''
    description: Check if the default configured value for whodata's 'queue_size' option. Also verify that the whodata
                 thread is started correctly.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Assert configured queue_size value is default value
            - Validate real-time whodata thread is started correctly
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.5.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders_module:
            type: fixture
            brief: Create a given list of folders when the module starts. Delete the folders at the end of the module.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options.conf file.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.

    assertions:
        - Verify configured queue_size value is default value
        - Verify real-time whodata thread is started correctly

    input_description: The file 'configuration_audit_buffer_default.yaml' provides the configuration
                       template.
                       The file 'cases_audit_buffer_default.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r".*Internal audit queue size set to \'(.*)\'."
        - r'.*File integrity monitoring (real-time Whodata) engine started.*'
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Detect configured value
    configured_value = get_configured_whodata_queue_size(wazuh_log_monitor)
    assert str(AUDIT_QUEUE_SIZE_DEFAULT_VALUE) in configured_value, 'Unexpected "queue_size" value found in ossec.log'

    # Detect real-time whodata thread started correctly
    detect_whodata_start(wazuh_log_monitor)


@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata),
                         ids=t2_test_case_ids)
def test_audit_buffer_values(configuration, metadata, test_folders, set_wazuh_configuration,
                             create_monitored_folders_module, configure_local_internal_options_function,
                             restart_syscheck_function):
    '''
    description: Check  when setting values to whodata's 'queue_size' option. The value is configured correctly.Also,
                 verify that the whodata thread is started correctly when value is inside valid range, and it fails
                 to start with values outside range and error messages are shown accordingly.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Assert configured queue_size value is default value
            - Validate real-time whodata thread is started correctly
            - On invalid values, validate error and that whodata does not start.
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.5.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders_module:
            type: fixture
            brief: Create a given list of folders when the module starts. Delete the folders at the end of the module.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options.conf file.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.

    assertions:
        - Verify when queue is full an event informs audit events may be lost
        - Verify when queue is full at start up audit healthcheck fails and does not start
        - Verify when using invalid values an error message is shown and does not start
        - Verify configured queue_size value
        - Verify real-time whodata thread is started correctly

    input_description: The file 'configuration_audit_buffer_values' provides the configuration template.
                       The file 'cases_audit_buffer_values.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r".*(Internal audit queue is full). Some events may be lost. Next scheduled scan will recover lost data."
        - r".*(Audit health check couldn't be completed correctly)."
        - fr".*Invalid value for element (\'{element}\': .*)"
        - r".*Internal audit queue size set to \'(.*)\'."
        - r'.*File integrity monitoring (real-time Whodata) engine started.*'
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if metadata['valid_range']:
        # Detect configured value
        configured_value = get_configured_whodata_queue_size(wazuh_log_monitor)
        assert str(metadata['queue_size']) in configured_value, 'Unexpected value found in "queue_size" in ossec.conf'

    if not metadata['audit_starts']:
        # Detect cause of failure
        if metadata['fail_reason'] == 'queue_full':
            detect_audit_queue_full(wazuh_log_monitor)
            detect_audit_healthcheck_failed(wazuh_log_monitor)
        elif metadata['fail_reason'] == 'invalid_value':
            detect_invalid_conf_value(wazuh_log_monitor, element='queue_size')
        with pytest.raises(TimeoutError):
            # Detect real-time whodata thread does not start
            detect_whodata_start(wazuh_log_monitor, timeout=T_5)
    else:
        # Detect real-time whodata thread started correctly
        detect_whodata_start(wazuh_log_monitor)
