'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh gathers information about the agent system (OS, hardware, packages, etc.) periodically in a DB and sends
       it to the manager, which finally stores this information in a DB. These tests check the different syscollector
       configurations and the complete scan process.

components:
    - modulesd

suite: syscollector

targets:
    - manager
    - agent

daemons:
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-db

os_platform:
    - linux
    - windows
    - macos

os_version:
    - CentOS 8
    - Ubuntu Bionic
    - macOS Catalina
    - Windows Server 2016
    - Windows Server 2019

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-syscollector.html
'''
import os
import sys

import pytest
from wazuh_testing import ANALYSISD_DAEMON, DB_DAEMON, MODULES_DAEMON, LOG_FILE_PATH, T_10, T_60
from wazuh_testing.modules import TIER0, SERVER, AGENT, LINUX, MACOS, WINDOWS
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.syscollector import event_monitor as evm


# Marks
pytestmark = [TIER0, SERVER, AGENT, LINUX, MACOS, WINDOWS]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Variables
local_internal_options = {'wazuh_modules.debug': 2}
if get_service() == 'wazuh-manager':
    daemons_handler_configuration = {'daemons': [ANALYSISD_DAEMON, DB_DAEMON, MODULES_DAEMON], 'ignore_errors': True}
elif sys.platform == 'win32':
    daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}
    local_internal_options = {'windows.debug': 2}
else:
    daemons_handler_configuration = {'daemons': [MODULES_DAEMON], 'ignore_errors': True}

# T1 Parameters: Check that Syscollector is disabled.
t1_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_syscollector_deactivation.yaml')
t1_config_parameters, t1_config_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_config_path, t1_config_parameters, t1_config_metadata)

# T2 Parameters: Check that each scan is disabled.
t2_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector_scans_disabled.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_all_scans_disabled.yaml')
t2_config_parameters, t2_config_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(t2_config_path, t2_config_parameters, t2_config_metadata)

# T3 Parameters: Check the behaviour of Syscollector while setting invalid configurations.
t3_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_invalid_configurations.yaml')
t3_config_parameters, t3_config_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_config_path, t3_config_parameters, t3_config_metadata)

# T4 Parameters: Check that Syscollector sets the default values when the configuration block is empty.
t4_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector_no_tags.yaml')
t4_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_default_values.yaml')
t4_config_parameters, t4_config_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)
t4_configurations = load_configuration_template(t4_config_path, t4_config_parameters, t4_config_metadata)

# T5 Parameters: Check that the scan is completed when all scans are enabled.
t5_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector.yaml')
t5_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_scanning.yaml')
t5_config_parameters, t5_config_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)
t5_config_metadata = t5_config_parameters
t5_configurations = load_configuration_template(t5_config_path, t5_config_parameters, t5_config_metadata)


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_config_metadata), ids=t1_case_ids)
def test_syscollector_deactivation(configuration, metadata, set_wazuh_configuration,
                                   configure_local_internal_options_module, truncate_monitored_files,
                                   daemons_handler_function):
    '''
    description: Check that syscollector is disabled.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Check if Syscollector was disabled.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if the syscollector module is disabled.

    input_description:
        - The `configuration_syscollector.yaml` file provides the module configuration for this test.
        - The `case_test_syscollector_deactivation.yaml` file provides the test cases.
    '''
    file_monitor = FileMonitor(LOG_FILE_PATH)
    evm.check_syscollector_is_disabled(file_monitor=file_monitor, timeout=T_10)


@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_config_metadata), ids=t2_case_ids)
def test_syscollector_all_scans_disabled(configuration, metadata, set_wazuh_configuration,
                                         configure_local_internal_options_module, truncate_monitored_files,
                                         daemons_handler_function):
    '''
    description: Check that each scan is disabled.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Check that no scan is triggered.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if a specific scan is disabled and not triggered.

    input_description:
        - The `configuration_syscollector_scans_disabled.yaml` file provides the module configuration for this test.
        - The `case_test_all_scans_disabled.yaml` file provides the test cases.
    '''
    check_functions = [evm.check_hardware_scan_started, evm.check_os_scan_started, evm.check_network_scan_started,
                       evm.check_packages_scan_started, evm.check_ports_scan_started, evm.check_processes_scan_started]
    # Add the hotfixes check if the platform is Windows.
    if sys.platform == 'win32':
        check_functions.append(evm.check_hotfixes_scan_started)

    # Check that no scan is triggered.
    for check_function in check_functions:
        # Expected: the function must throw a TimoutError
        with pytest.raises(TimeoutError):
            file_monitor = FileMonitor(LOG_FILE_PATH)
            check_function(file_monitor=file_monitor)
            pytest.fail('It seems that a scan was triggered.' \
                        f"This check has a match in the log: {check_function.__name__}")


@pytest.mark.xfail(sys.platform == "win32", reason='Reported in wazuh/wazuh#15412')
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_config_metadata), ids=t3_case_ids)
def test_syscollector_invalid_configurations(configuration, metadata, set_wazuh_configuration,
                                             configure_local_internal_options_module, truncate_monitored_files,
                                             daemons_handler_function):
    '''
    description: Check the behaviour of Syscollector while setting invalid configurations.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Skip test if the field is hotfixes and the platform is not Windows.
            - Check if the tag/attribute error is present in the logs.
            - Check if Syscollector starts depending on the criticality of the field.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if the scan is triggered after N seconds.
        - Check if a specific scan is disabled and not triggered.

    input_description:
        - The `configuration_syscollector.yaml` file provides the module configuration for this test.
        - The `case_test_invalid_configurations.yaml` file provides the test cases.
    '''
    field = metadata['field']
    attribute = metadata['attribute']
    non_critical_fields = ('max_eps')
    file_monitor = FileMonitor(LOG_FILE_PATH)

    # Skip test if the field is hotfixes and the platform is not Windows.
    if field == 'hotfixes' and sys.platform != 'win32':
        pytest.skip('The hotfixes scan is exclusive of Windows agents.')

    # If the field has no value, it means that the test should search for the attribute error in the logs, not for the
    # tag error.
    if field is not None:
        evm.check_tag_error(file_monitor=file_monitor, field=field)
    else:
        evm.check_attr_error(file_monitor=file_monitor, attr=attribute)

    # Check that the module has started if the field is not critical
    if field in non_critical_fields:
        file_monitor = FileMonitor(LOG_FILE_PATH)
        evm.check_module_is_starting(file_monitor=file_monitor)
    else:
        # Check that the module does not start if the field is critical
        with pytest.raises(TimeoutError):
            evm.check_module_is_starting(file_monitor=file_monitor)
            pytest.fail(f"The module has started anyway. This behaviour is not the expected.")


@pytest.mark.parametrize('configuration, metadata', zip(t4_configurations, t4_config_metadata), ids=t4_case_ids)
@pytest.mark.xfail(reason='Reported in wazuh/wazuh#15413')
def test_syscollector_default_values(configuration, metadata, set_wazuh_configuration,
                                     configure_local_internal_options_module, truncate_monitored_files,
                                     daemons_handler_function):
    '''
    description: Check that Syscollector sets the default values when the configuration block is empty.

    test_phases:
        - Configure syscollector.
        - Configure modulesd in debug mode.
        - Truncate the log.
        - Restart analysisd, wazuh-db and modulesd

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if the module sets the default configuration.

    input_description:
        - The `configuration_syscollector_no_tags.yaml` file provides the module configuration for this test.
        - The `case_test_default_values.yaml` file provides the test cases.
    '''
    file_monitor = FileMonitor(LOG_FILE_PATH)
    evm.check_config(file_monitor=file_monitor)
    evm.check_module_startup_finished(file_monitor=file_monitor)


@pytest.mark.parametrize('configuration, metadata', zip(t5_configurations, t5_config_metadata), ids=t5_case_ids)
def test_syscollector_scannig(configuration, metadata, set_wazuh_configuration,
                              configure_local_internal_options_module, truncate_monitored_files,
                              daemons_handler_function):
    '''
    description: Check that the scan is completed when all scans are enabled.

    test_phases:
        - Configure syscollector.
        - Configure modulesd in debug mode.
        - Truncate the log.
        - Restart analysisd, wazuh-db and modulesd

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if each scan is completed.
        - Check if the synchronization is completed.

    input_description:
        - The `configuration_syscollector.yaml` file provides the module configuration for this test.
        - The `case_test_scanning.yaml` file provides the test cases.
    '''
    file_monitor = FileMonitor(LOG_FILE_PATH)
    # 60s + 2 seconds of margin because it includes the case when the agent starts for the first time
    evm.check_module_is_starting(file_monitor=file_monitor, timeout=T_60 + 2, update_position=False)
    # Check general scan has started
    evm.check_scan_started(file_monitor=file_monitor, timeout=T_10, update_position=False)

    # Check that each scan was accomplished
    checks_to_run = [evm.check_hardware_scan_finished, evm.check_os_scan_finished, evm.check_network_scan_finished,
                     evm.check_packages_scan_finished, evm.check_ports_scan_finished, evm.check_processes_scan_finished]
    if sys.platform == 'win32':
        checks_to_run.append(evm.check_hotfixes_scan_finished)

    for check_runner in checks_to_run:
        # Run check
        check_runner(file_monitor=file_monitor, timeout=T_10, update_position=False)

    # Check general scan has finished
    evm.check_scan_finished(file_monitor=file_monitor, timeout=T_10, update_position=False)
    # Check that the sync has finished
    evm.check_sync_finished(file_monitor=file_monitor, timeout=T_10, update_position=False)
