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

from wazuh_testing import global_parameters
from wazuh_testing.processes import check_if_daemons_are_running, execute_shell_command
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import remove_file
from wazuh_testing.tools import CUSTOM_RULES_PATH, LOCAL_RULES_PATH, AR_SCRIPTS_PATH

pytestmark = [pytest.mark.tier(level=2), pytest.mark.server]

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
wazuh_ar_script = os.path.join(AR_SCRIPTS_PATH, 'custom-ar.sh')
output_custom_ar_script = '/tmp/file-ar.txt'
source_path = [custom_rule, local_rules, custom_ar_script]
destination_path = [f"{CUSTOM_RULES_PATH}/0270-web_appsec_rules_edit.xml", LOCAL_RULES_PATH, wazuh_ar_script]


# Test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


@pytest.mark.parametrize("source_path", [source_path])
@pytest.mark.parametrize("destination_path", [destination_path])
@pytest.mark.parametrize("file_to_monitor", ['/tmp/file_to_monitor.log'])
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_overwritten_rules_ar(configuration, metadata, create_file_to_monitor, file_to_monitor,
                              set_wazuh_configuration_analysisd, copy_file, source_path, destination_path,
                              restart_wazuh_daemon_function):
    '''
    description: Check if 'active response' works correctly when binding an active response for a rule that will be overwritten.

    wazuh_min_version: 4.3.5

    parameters:
        - configuration:
            type: fixture
            brief: Get configurations from the module.
        - metadata:
            type: fixture
            brief: Get metadata from the module.
        - create_file_to_monitor:
            type: fixture
            brief: Create a file to will monitored by Wazuh.
        - file_to_monitor:
            type: parametrize
            brief:  Path of file that will monitored by Wazuh.
        - set_wazuh_configuration_analysisd:
            type: fixture
            brief:  Set configurations from the module.
        - copy_file:
            type: fixture
            brief:  Copy file from source to destination.
        - source_path:
            type: parametrize
            brief: list that contains sources path of files.
        - destination_path:
            type: parametrize
            brief: list that contains destinations path of files.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: restart Wazuh.
        
    assertions:
        - verify that the custom AR created a file.

    input_description: Different use cases are found in the test module.

    expected_output:
        - A file was successfully created by AR.

    tags:
        - ar_analysisd
    '''
    os.chmod(wazuh_ar_script, 0o777)
    cmd = "echo '{}' >> '{}'".format(metadata['log_sample'], file_to_monitor)
    execute_shell_command(cmd)

    # Checking if AR works properly
    time.sleep(global_parameters.default_timeout)
    assert os.path.exists(output_custom_ar_script)

    # Check that wazuh-analysisd is running and has not crashed when trying to parse files with unexpected file types
    check_if_daemons_are_running(['wazuh-analysisd'])

    # Remove file created by active response
    remove_file(output_custom_ar_script)
