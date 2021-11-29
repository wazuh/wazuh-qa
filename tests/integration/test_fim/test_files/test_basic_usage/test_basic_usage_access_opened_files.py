"""
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Check that files that are being scanned by the syscheckd daemon can
       modified (renamed/deleted), and that wazuh is not blocking the files.

tier: 0

modules:
    - syscheck

components:
    - manager
    - agent

path: tests/integration/test_fim/test_files/test_basic_usage/test_basic_usage_access_opened_files.py

daemons:
    - wazuh-syscheckd

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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/vuln-detector.html#enabled

tags:
    - syscheck
"""

import os
import random
import string
import pytest
import time

from wazuh_testing.fim import (
    LOG_FILE_PATH,
    generate_params,
    detect_initial_scan_start,
    get_scan_timestamp,
)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import (
    load_wazuh_configurations,
    check_apply_test,
)
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import delete_path_recursively


# Marks
pytestmark = [pytest.mark.tier(level=0)]

# Variables
directory_str = os.path.join(PREFIX, "testdir1")
file_path = os.path.join(directory_str, "large_file")
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
configurations_path = os.path.join(test_data_path, "wazuh_conf.yaml")

# configurations
conf_params = {"TEST_DIRECTORIES": directory_str, "MODULE_NAME": __name__}
parameters, metadata = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(
    configurations_path, __name__, params=parameters, metadata=metadata
)


# Fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="function")
def create_and_delete_large_file(get_configuration, request):
    """
    Create a large file and later delete the path.
    """
    if get_configuration["metadata"]["fim_mode"] != "scheduled":
        pytest.skip("This test does not apply to realtime or whodata modes")
    # If path exists delete it
    if os.path.exists(directory_str):
        delete_path_recursively(directory_str)
    # create directory
    os.mkdir(directory_str)
    file_size = 1024 * 1024 * 960  # 968 MB
    chunksize = 1024 * 768
    # create file and write to it.
    with open(file_path, "a") as f:
        while os.stat(file_path).st_size < file_size:
            f.write(random.choice(string.printable) * chunksize)
    yield
    # delete the file and path
    delete_path_recursively(directory_str)


@pytest.fixture(scope="function")
def wait_for_scan_start(get_configuration, request):
    """
    Wait for start of initial FIM scan.
    """
    file_monitor = getattr(request.module, "wazuh_log_monitor")
    try:
        detect_initial_scan_start(file_monitor)
    except KeyError:
        detect_initial_scan_start(file_monitor)


# Tests
@pytest.mark.parametrize(
    "operation, tags_to_apply", [("delete", {"ossec_conf"}), ("rename", {"ossec_conf"})]
)
def test_basic_usage_access_opened_files(
    operation,
    tags_to_apply,
    get_configuration,
    configure_environment,
    create_and_delete_large_file,
    restart_syscheckd_function,
    wait_for_scan_start,
):
    """
    description: Check that files that are being scanned by syscheckd daemon
                 can modified (renamed/deleted), and that wazuh is not
                 blocking the files.

    wazuh_min_version: 4.3

    parameters:
        - operation:
            type: string
            brief: Tells which operation has to be performed.
        - tags_to_apply:
            type: string
            brief: Tells which configuration to use.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - create_and_delete_large_file:
            type: fixture
            brief: Creates file to be monitored. Cleans enviroment after test.
        - restart_syscheckd_function:
            type: fixture
            brief: Restart the `wazuh-syscheckd` daemon.
        - wait for scan start:
            type: fixture
            brief: Wait for start of initial FIM scan start.

    assertions:
        - Verify that the file hast been modified (renamed/deleted).
        - Verify that the modificaction is done before the initial scan ends.

    input_description: Two use cases are found in the test module and include
                       parameters for operation (`delete` and `rename`).
    """

    check_apply_test(tags_to_apply, get_configuration["tags"])

    # Wait a few seconds for scan to run on created file.
    time.sleep(3)

    modify_time = None
    # Modify/Delete the file
    if operation == "rename":
        changed_path = os.path.join(directory_str, "changed_name")
        try:
            modify_time = time.time()
            os.rename(file_path, changed_path)
            # Assert the file has been changed
            assert os.path.isfile(changed_path) == True
        except (OSError, IOError, PermissionError) as error:
            pytest.fail(f"Could not rename file - Error: {error}")
    elif operation == "delete":
        try:
            os.remove(file_path)
            modify_time = time.time()
            # Assert the file has been deleted
            assert os.path.isfile(file_path) == False
        except (OSError, IOError, PermissionError) as error:
            pytest.fail(f"Could not delete file - Error: {error}")

    # Capture scan end timestamp & assert the file was modified before scan end
    scan_timestamp = get_scan_timestamp(wazuh_log_monitor)
    assert modify_time < scan_timestamp
