'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Active responses perform various countermeasures to address active threats, such as blocking access
       to an agent from the threat source when certain criteria are met.

tier: 2

modules:
    - active_response

components:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/active-response/#active-response

tags:
    - ar_analysisd
'''
import os
import pytest
import time

from wazuh_testing.processes import check_if_daemons_are_running, run_local_command_printing_output
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import remove_file
from wazuh_testing import T_5
from wazuh_testing.tools import CUSTOM_RULES_PATH, LOCAL_RULES_PATH, ACTIVE_RESPONSE_BINARY_PATH

pytestmark = [pytest.mark.tier(level=1), pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
RULES_PATH = os.path.join(TEST_DATA_PATH, 'rules')
CUSTOM_AR_SCRIPT_PATH = os.path.join(TEST_DATA_PATH, 'scripts')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_overwritten_rules.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_overwritten_rules.yaml')
custom_rule = os.path.join(RULES_PATH, '0270-web_appsec_rules_edit.xml')
local_rules = os.path.join(RULES_PATH, 'local_rules.xml')
custom_ar_script = os.path.join(CUSTOM_AR_SCRIPT_PATH, 'custom-ar.sh')
wazuh_ar_script = os.path.join(ACTIVE_RESPONSE_BINARY_PATH, 'custom-ar.sh')
output_custom_ar_script = '/tmp/file-ar.txt'
source_path = [custom_rule, local_rules, custom_ar_script]
destination_path = [f"{CUSTOM_RULES_PATH}/0270-web_appsec_rules_edit.xml", LOCAL_RULES_PATH, wazuh_ar_script]
file_to_monitor = '/tmp/file_to_monitor.log'

# Test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


@pytest.fixture(scope='function')
def clean_AR_file():
    "Remove in teardown the file created by the active response"
    yield
    remove_file(output_custom_ar_script)


@pytest.mark.parametrize("source_path", [source_path], ids=[''])
@pytest.mark.parametrize("destination_path", [destination_path], ids=[''])
@pytest.mark.parametrize("new_file_path", [file_to_monitor], ids=[''])
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_overwritten_rules_ar(configuration, metadata, source_path, destination_path, new_file_path,
                              create_file, set_wazuh_configuration, copy_file, truncate_monitored_files,
                              restart_wazuh_function, clean_AR_file):
    '''
    description: Check if active response works correctly for the following cases:
        - An active response is triggered when an event matches with a rule.
        - An active response is triggered when an event matches with an overwritten rule.
        - An active response is triggered when an event matches with a rule of depth > 0.
        - An active response is triggered when an event matches with an overwritten rule of depth > 0.

    test_phases:
        - setup:
            - Copy custom rule and active response files to Wazuh paths.
            - Create a new file which will be monitored with logcollector.
            - Set wazuh configuration. Add active_response, command and localfile blocks.
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Add a custom log in a monitored file to generate an event that triggers a rule that trigger an AR.
            - Check if the active response has been triggered (checking if a file has been created).
            - Check that wazuh-analysisd is running (it has not been crashed).
        - teardown:
            - Remove generated file when triggering the active response.
            - Restart initial wazuh configuration.
            - Remove generated and custom copied files.

    wazuh_min_version: 4.3.5

    parameters:
        - configuration:
            type: fixture
            brief: Get configurations from the module.
        - metadata:
            type: fixture
            brief: Get metadata from the module.
        - source_path:
            type: parametrize
            brief: list that contains sources path of files.
        - destination_path:
            type: parametrize
            brief: list that contains destinations path of files.
        - new_file_path:
            type: parametrize
            brief: File path to create.
        - create_file:
            type: fixture
            brief: Create a file to be monitored by Wazuh.
        - set_wazuh_configuration:
            type: fixture
            brief:  Set Wazuh custom configuration.
        - copy_file:
            type: fixture
            brief:  Copy file from source to destination.
        - truncate_monitored_files:
            type: fixture
            brief:  Truncate wazuh log files.
        - restart_wazuh_function:
            type: fixture
            brief: restart Wazuh.
        - clean_AR_file:
            type: fixture
            brief: Clean generated AR file.

    assertions:
        - Check that the AR is triggered.
        - Check that wazuh-analysisd daemon does not crash.

    input_description:
        - The `configuration_overwritten_rules` file provides the module configuration for this test.
        - The `cases_overwritten_rules` file provides the test cases.
    '''
    # Set all permissions for wazuh to be able to use the custom active response
    os.chmod(wazuh_ar_script, 0o777)

    # Write a line in a monitored file with logcollector for generating an event that matches with a custom rule
    cmd = "echo '{}' >> '{}'".format(metadata['log_sample'], file_to_monitor)
    run_local_command_printing_output(cmd)

    # Waiting time for triggering the rule and AR.
    time.sleep(T_5)

    # Checking if AR works properly
    assert os.path.exists(output_custom_ar_script), "The active response has not been triggered"

    # Check that wazuh-analysisd is running and has not crashed
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd daemon is not running. ' \
                                                                 'Maybe it has crashed'
