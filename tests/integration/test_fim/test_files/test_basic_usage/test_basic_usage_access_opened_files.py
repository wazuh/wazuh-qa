"""
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Check that files that are being scanned by the syscheckd daemon can
       modified (renamed/deleted), and that wazuh is not blocking the files.

tier: 1

modules:
    - syscheck

components:
    - manager
    - agent

path: tests/integration/test_fim/test_files/test_basic_usage/test_basic_usage_access_opened_files.py

daemons:
    - wazuh-syscheckd

modes:
    - scheduled

os_platform:
    - linux
    - windows
    - solaris
    - macos

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
    - Windows 10

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/fim-configuration.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html

tags:
    - syscheck
"""

import os
import random
import string
import pytest
import time

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, get_scan_timestamp
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import delete_path_recursively, create_large_file

from wazuh_testing.tools.file import delete_file, rename_file


# Marks
pytestmark = [pytest.mark.tier(level=1)]

# Variables
directory_str = os.path.join(PREFIX, "testdir1")
filenames = ["large_file","changed_name"]
file_path = os.path.join(directory_str, filenames[0])
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
configurations_path = os.path.join(test_data_path, "wazuh_conf.yaml")
sleep_time = 3

# configurations
conf_params = {"TEST_DIRECTORIES": directory_str, "MODULE_NAME": __name__}
parameters, metadata = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# Fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="function")
def create_and_delete_file(request):
    """Creates a file and later deletes the path."""

    create_large_file(directory_str, file_path)
    yield
    delete_path_recursively(directory_str)


# Tests
@pytest.mark.parametrize("tags_to_apply", [({"ossec_conf"})])
def test_basic_usage_modify_opened_files(tags_to_apply, get_configuration, configure_environment, 
                                        create_and_delete_file, restart_syscheckd_function, wait_for_scan_start):
    """
    description: Check that files that are being scanned by syscheckd daemon
                 can modified (renamed), and that wazuh is not
                 blocking the files.

    wazuh_min_version: 4.2

    parameters:
        - tags_to_apply:
            type: string
            brief: Tells which configuration to use.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - create_and_delete_file:
            type: fixture
            brief: Creates file to be monitored. Cleans enviroment after test.
        - restart_syscheckd_function:
            type: fixture
            brief: Restart the `wazuh-syscheckd` daemon.
        - wait for scan start:
            type: fixture
            brief: Wait for start of initial FIM scan start.

    assertions:
        - Verify that the modificaction is done before the initial scan ends.
    """

    check_apply_test(tags_to_apply, get_configuration["tags"])

    # Wait a few seconds for scan to run on created file.
    time.sleep(sleep_time)

    modify_time = None
    # Modify the file
    try:
        renamed_path = os.path.join(directory_str, filenames[1])
        modify_time = time.time()
        rename_file(file_path, renamed_path)
    except (OSError, IOError, PermissionError) as error:
        pytest.fail(f"Could not rename file - Error: {error}")

    # Capture scan end timestamp & assert the file was modified before scan end
    scan_timestamp = get_scan_timestamp(wazuh_log_monitor)
    assert modify_time < scan_timestamp


@pytest.mark.parametrize("tags_to_apply", [({"ossec_conf"})])
def test_basic_usage_delete_opened_files(tags_to_apply, get_configuration, configure_environment,
                                        create_and_delete_file, restart_syscheckd_function, wait_for_scan_start):
    """
    description: Check that files that are being scanned by syscheckd daemon
                 can deleted, and that wazuh is not
                 blocking the files.

    wazuh_min_version: 4.2

    parameters:
        - tags_to_apply:
            type: string
            brief: Tells which configuration to use.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - create_and_delete_file:
            type: fixture
            brief: Creates file to be monitored. Cleans enviroment after test.
        - restart_syscheckd_function:
            type: fixture
            brief: Restart the `wazuh-syscheckd` daemon.
        - wait for scan start:
            type: fixture
            brief: Wait for start of initial FIM scan start.

    assertions:
        - Verify that the modificaction is done before the initial scan ends.

    """

    check_apply_test(tags_to_apply, get_configuration["tags"])

    # Wait a few seconds for scan to run on created file.
    time.sleep(sleep_time)

    modify_time = None
    # Delete the file
    try:
        delete_file(file_path)
        modify_time = time.time()
    except (OSError, IOError, PermissionError) as error:
        pytest.fail(f"Could not delete file - Error: {error}")

    # Capture scan end timestamp & assert the file was modified before scan end
    scan_timestamp = get_scan_timestamp(wazuh_log_monitor)
    assert modify_time < scan_timestamp
