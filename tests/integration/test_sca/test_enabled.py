'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the `enabled` option of the SCA module
       is working correctly. This option is located in its corresponding section of
       the `ossec.conf` file and allows enabling or disabling this module.

components:
    - sca

targets:
    - manager
    - agent
daemons:
    - wazuh-modulesd

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html

tags:
    - sca
'''
import os
import pytest

from wazuh_testing import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.sca import event_monitor as evm
from wazuh_testing.modules.sca import SCA_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_enabled.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_enabled.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


@pytest.mark.parametrize('local_internal_options', [local_internal_options], ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_enabled(configuration, metadata, local_internal_options, prepare_cis_policies_file, truncate_monitored_files,
                 set_wazuh_configuration_with_local_internal_options, restart_wazuh_function):
    '''
    description: Check that sca is started when is set enabled yes. When enabled is set to no, the test will
                 check that the sca is disabled and does not start.

    test_phases:
        - Set a custom Wazuh configuration.
        - Restart wazuh.
        - Check in the log that the sca module started appears.
        - Check that sca scan starts and finishes

    test_phases:
        - Copy cis_sca ruleset file into agent.
        - Restart wazuh.
        - Check that sca module starts if enabled is set to 'yes', or is disabled if enabled is set to 'no'


    wazuh_min_version: 4.5.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - prepare_cis_policies_file:
            type: fixture
            brief: copy test sca policy file. Delete it after test.
        - set_wazuh_configuration_with_local_internal_options:
            type: fixture
            brief: Set the wazuh configuration and local_internal_options according to the configuration data.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_modulesd_function:
            type: fixture
            brief: Restart the wazuh-modulesd daemon.
        - wait_for_sca_enabled:
            type: fixture
            brief: Wait for the sca Module to start before starting the test.

    assertions:
        - Verify that when the `enabled` option is set to `yes`, the SCA module is enabled.
        - Verify the sca scan starts.
        - Verify the sca scan ends.

    input_description:
        - The `cases_scan_results.yaml` file provides the module configuration for this test.
        - the cis*.yaml files located in the policies folder provide the sca rules to check.

    expected_output:
        - r".*sca.*INFO: (Module disabled). Exiting."
        - r'.*sca.*INFO: (Module started.)'
        - r'.*sca.*INFO: (Starting Security Configuration Assessment scan).'
        - r".*sca.*INFO: Security Configuration Assessment scan finished. Duration: (\\d+) seconds."
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    if metadata['enabled'] is False:
        evm.check_sca_disabled(wazuh_log_monitor)
    else:
        evm.check_sca_enabled(wazuh_log_monitor)
        evm.check_sca_scan_started(wazuh_log_monitor)
        evm.check_sca_scan_ended(wazuh_log_monitor)
