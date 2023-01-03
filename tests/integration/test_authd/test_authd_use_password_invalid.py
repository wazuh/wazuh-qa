'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if a set of wrong configuration option values in the block force
       are warned in the logs file.

components:
    - authd

suite: force_options

targets:
    - manager

daemons:
    - wazuh-authd

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

tags:
    - enrollment
    - authd
'''

import pytest

from pathlib import Path

from wazuh_testing.modules.authd import event_monitor as evm
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
# from wazuh_testing.tools.file import write_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools.services import control_service

# Constants & base paths
TEST_NAME = Path(__file__).stem.replace('test_', '')
DATA_PATH = Path(Path(__file__).parent, 'data')
TESTS_CASES_PATH = Path(DATA_PATH, 'test_cases')
CONFIGS_PATH = Path(DATA_PATH, 'config_templates')

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Paths
cases_path = Path(TESTS_CASES_PATH, f"cases_{TEST_NAME}.yaml")
config_path = Path(CONFIGS_PATH, f"config_{TEST_NAME}.yaml")

# Configurations and test cases
params, metadata, case_ids = get_test_cases_data(cases_path)
configuration = load_configuration_template(config_path, params, metadata)
local_internal_options = {'authd.debug': '2'}


# Tests
@pytest.mark.parametrize('metadata, configuration', zip(metadata, configuration), ids=case_ids)
def test_authd_force_options_invalid_config(metadata: dict, configuration: dict, truncate_monitored_files: None,
                                            configure_local_internal_options_module: None):
    '''
    description:
        Checks that every input with a wrong configuration option value
        matches the adequate output log. None force registration
        or response message is made.

    wazuh_min_version:
        4.5.0

    tier: 0

    parameters:
        - get_current_test_case:
            type: fixture
            brief: gets the current test case from the tests' list
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - override_authd_force_conf:
            type: fixture
            brief: Modified the authd configuration options.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The received output must match with expected due to wrong configuration options.

    input_description:
        Different test cases are contained in an external YAML file (invalid_config folder) which includes
        different possible wrong settings.

    expected_output:
        - Invalid configuration values error.
    '''
    # The expected error log must be defined.
    if not metadata.get('error'):
        raise ValueError('Expected error not provided.')

    # Verify wazuh-manager fails at restart.
    with pytest.raises(ValueError):
        control_service('restart')

    # Verify the error log is raised.
    evm.check_authd_event(callback=metadata.get('error'))
