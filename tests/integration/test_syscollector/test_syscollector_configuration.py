'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh gathers information about the agent system (OS, hardware, packages, etc.) periodically in a DB and sends
       it to the manager, which finally stores this information in a DB.

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
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Fedora 31
    - Fedora 32
    - Fedora 33
    - Fedora 34
    - openSUSE 42
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - SUSE 12
    - SUSE 13
    - SUSE 14
    - SUSE 15
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial
    - Ubuntu Focal
    - macOS Server
    - macOS Sierra
    - macOS Catalina
    - Windows XP
    - Windows 7
    - Windows 8
    - Windows 10
    - Windows Server 2003
    - Windows Server 2012
    - Windows Server 2016
    - Windows Server 2019

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-syscollector.html
'''
import os
import sys
from datetime import datetime

import pytest
from wazuh_testing import ANALYSISD_DAEMON, DB_DAEMON, MODULES_DAEMON, DB_PATH, LOG_FILE_PATH, SYSCOLLECTOR_DB_PATH, \
                          T_10, T_30
from wazuh_testing.db_interface import global_db
from wazuh_testing.modules import TIER0, SERVER, AGENT, LINUX, MACOS, WINDOWS
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import remove_file
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

# T1 Parameters
t1_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_syscollector_deactivation.yaml')
t1_config_parameters, t1_config_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_config_path, t1_config_parameters, t1_config_metadata)

# T2 Parameters
t2_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector_scans_disabled.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_all_scans_disabled.yaml')
t2_config_parameters, t2_config_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(t2_config_path, t2_config_parameters, t2_config_metadata)

# T3 Parameters
t3_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_invalid_configurations.yaml')
t3_config_parameters, t3_config_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_config_path, t3_config_parameters, t3_config_metadata)

# T4 Parameters
t4_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector_no_tags.yaml')
t4_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_default_values.yaml')
t4_config_parameters, t4_config_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)
t4_configurations = load_configuration_template(t4_config_path, t4_config_parameters, t4_config_metadata)

# T5 Parameters
t5_config_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_syscollector.yaml')
t5_cases_path = os.path.join(TEST_CASES_PATH, 'case_test_scanning.yaml')
t5_config_parameters, t5_config_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)
t5_configurations = load_configuration_template(t5_config_path, t5_config_parameters, t5_config_metadata)


# Fixtures
@pytest.fixture(scope='function')
def remove_agent_syscollector_info(agent_id='000'):
    """Removes the previous scan information.

    Args:
        agent_id (str): ID of the agent whose information will be removed.
    """
    if get_service() == 'wazuh-agent':
        # Remove local DB
        remove_file(SYSCOLLECTOR_DB_PATH)
    else:
        # Remove from global db
        global_db.delete_agent(agent_id)
        # Remove agent id DB file
        remove_file(os.path.join(DB_PATH, f"{agent_id}.db"))


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_config_metadata), ids=t1_case_ids)
def test_syscollector_deactivation(configuration, metadata, set_wazuh_configuration,
                                   configure_local_internal_options_module, truncate_log_file,
                                   daemons_handler_function):
    '''
    description: Check that the module is disabled.

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
        - truncate_log_file:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler_function:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if the syscollector module is disabled.

    input_description:
        - The `configuration_syscollector.yaml` file provides the module configuration for this test.
        - The `case_test_syscollector_deactivation.yaml` file provides the test cases.
    '''
    file_monitor = FileMonitor(LOG_FILE_PATH) if sys.platform == 'win32' else None
    evm.check_disabled(file_monitor=file_monitor, timeout=T_10)


@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_config_metadata), ids=t2_case_ids)
def test_syscollector_all_scans_disabled(configuration, metadata, set_wazuh_configuration,
                                         configure_local_internal_options_module, truncate_log_file,
                                         daemons_handler_function):
    '''
    description: Check that each scan is disabled.

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
        - truncate_log_file:
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
    file_monitor = None
    check_functions = [evm.check_hardware_scan_started, evm.check_os_scan_started, evm.check_network_scan_started,
                       evm.check_packages_scan_started, evm.check_ports_scan_started, evm.check_processes_scan_started]
    if sys.platform == 'win32':
        check_functions.append(evm.check_hotfixes_scan_started)

    # Check that no scan is triggered
    for check_f in check_functions:
        # Expected: the function must throw a TimoutError
        with pytest.raises(TimeoutError):
            # Overwrite the default timeout (because the test configuration)
            file_monitor = FileMonitor(LOG_FILE_PATH)
            check_f(file_monitor=file_monitor, timeout=T_10)
            pytest.fail(f"It seems that a scan was triggered. This check has a match in the log: {check_f.__name__}")


@pytest.mark.xfail(reason='Reported in wazuh/wazuh#15412')
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_config_metadata), ids=t3_case_ids)
def test_syscollector_invalid_configurations(configuration, metadata, set_wazuh_configuration,
                                             configure_local_internal_options_module, truncate_log_file,
                                             daemons_handler_function):
    '''
    description: Check the behaviour of the module while setting invalid configurations.

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
        - truncate_log_file:
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
    file_monitor = FileMonitor(LOG_FILE_PATH) if sys.platform == 'win32' else None

    if field is not None:
        if field == 'hotfixes' and sys.platform != 'win32':
            return True

        evm.check_tag_error(file_monitor=file_monitor, field=field, timeout=T_10)

        if field in non_critical_fields:
            # Check that the module has started if the field is not critical
            file_monitor = FileMonitor(LOG_FILE_PATH)
            evm.check_has_started(file_monitor=file_monitor, timeout=T_10)
            return True
    else:
        evm.check_attr_error(file_monitor=file_monitor, attr=attribute, timeout=T_10)

    # Check that the module does not start
    with pytest.raises(TimeoutError):
        evm.check_has_started(file_monitor=file_monitor, timeout=T_10)
        pytest.fail(f"The module has started anyway. This behaviour is not the expected.")


@pytest.mark.parametrize('configuration, metadata', zip(t4_configurations, t4_config_metadata), ids=t4_case_ids)
@pytest.mark.xfail(reason='Reported in wazuh/wazuh#15413')
def test_syscollector_default_values(configuration, metadata, set_wazuh_configuration,
                                     configure_local_internal_options_module, truncate_log_file,
                                     daemons_handler_function):
    '''
    description: Check that the module sets the default values when the configuration block is empty.

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
        - truncate_log_file:
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
    file_monitor = FileMonitor(LOG_FILE_PATH) if sys.platform == 'win32' else None
    evm.check_config(file_monitor=file_monitor, timeout=T_10)


@pytest.mark.parametrize('configuration, metadata', zip(t5_configurations, t5_config_metadata), ids=t5_case_ids)
def test_syscollector_scannig(configuration, metadata, set_wazuh_configuration,
                              configure_local_internal_options_module, truncate_log_file,
                              remove_agent_syscollector_info, daemons_handler_function):
    '''
    description: Check that the module sets the default values when the configuration block is empty.

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
        - truncate_log_file:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - remove_agent_syscollector_info:
            type: fixture
            brief: Removes the previous scan information.
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
    file_monitor = FileMonitor(LOG_FILE_PATH) if sys.platform == 'win32' else None
    evm.check_has_started(file_monitor=file_monitor, timeout=T_30)
    # Check general scan has started
    evm.check_scan_started(file_monitor=file_monitor, timeout=T_10)

    # Check that each scan was accomplished
    scan_checks = [evm.check_hardware_scan_finished, evm.check_os_scan_finished, evm.check_network_scan_finished,
                   evm.check_packages_scan_finished, evm.check_ports_scan_finished, evm.check_processes_scan_finished]
    if sys.platform == 'win32':
        scan_checks.append(evm.check_hotfixes_scan_finished)

    for check in scan_checks:
        # Run check
        file_monitor = FileMonitor(LOG_FILE_PATH)
        check(file_monitor=file_monitor, timeout=T_10)

    # Check general scan has finished
    evm.check_scan_finished(file_monitor=file_monitor, timeout=T_10)
    # Check that the sync has finished
    evm.check_sync_finished(file_monitor=file_monitor, timeout=T_10)
