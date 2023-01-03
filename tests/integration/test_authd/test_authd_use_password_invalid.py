'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check invalid values in the authd.pass (for now just checks 'empty')
       raises the expected error logs.

components:
    - authd

suite: use_password

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
from wazuh_testing.tools import DEFAUL_AUTHD_PASS_PATH
from wazuh_testing.tools.file import write_file, delete_file
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
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


# Fixture
@pytest.fixture()
def set_authd_pass(metadata: dict):
    """Configure the file 'authd.pass' as needed for the test."""
    # Set the content.
    if metadata.get('password') == 'empty':
        authd_pass_content = ''
    else:
        authd_pass_content = metadata.get('password')
    # Write the content in the authd.pass file.
    write_file(DEFAUL_AUTHD_PASS_PATH, authd_pass_content)
    yield
    # Delete the file as by default it doesn't exist.
    delete_file(DEFAUL_AUTHD_PASS_PATH)


# Test
@pytest.mark.parametrize('metadata, configuration', zip(metadata, configuration), ids=case_ids)
def test_authd_use_password_invalid(metadata: dict, configuration: dict, truncate_monitored_files: None,
                                    configure_local_internal_options_module: None, set_authd_pass: None,
                                    set_wazuh_configuration: None, tear_down: None):
    '''
    description:
        Checks that every invalid input reproduces the expected results and
        raises the correct logs.

    wazuh_min_version:
        4.5.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - set_authd_pass:
            type: fixture
            brief: Configures the `authd.pass` file as needed.

    assertions:
        - The raised error must match with the expected.

    input_description:
        Different test cases are contained in an external YAML file which includes
        different possible wrong settings.

    expected_output:
        - Invalid password error.
    '''
    # The expected error log must be defined.
    if not metadata.get('error'):
        raise ValueError('Expected error not provided.')

    # Verify wazuh-manager fails at restart.
    with pytest.raises(ValueError):
        control_service('restart')

    # Verify the error log is raised.
    evm.check_authd_event(callback=metadata.get('error'))
