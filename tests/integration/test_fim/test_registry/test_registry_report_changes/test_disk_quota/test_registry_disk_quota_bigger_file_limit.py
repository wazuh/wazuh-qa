"""
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM limits the size of
       the 'queue/diff/local' folder where Wazuh stores the compressed files used to perform
       the 'diff' operation when the 'disk_quota' limit is set.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_report_changes_disk_quota

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#disk-quota

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_report_changes
"""
import os

import pytest
from wazuh_testing import LOG_FILE_PATH, global_parameters
from wazuh_testing.modules.fim import (WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, MONITORED_KEY_2, KEY_WOW64_32KEY,
                                       KEY_WOW64_64KEY, SIZE_LIMIT_CONFIGURED_VALUE)
from wazuh_testing.modules.fim.event_monitor import ERR_MSG_CONTENT_CHANGES_EMPTY, ERR_MSG_CONTENT_CHANGES_NOT_EMPTY
from wazuh_testing.modules.fim.utils import (generate_params, calculate_registry_diff_paths, registry_value_create,
                                             registry_value_update, registry_value_delete, create_values_content)
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

test_regs = [os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY),
             os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY_2)]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
scan_delay = 10

# Configurations

params, metadata = generate_params(modes=["scheduled"], extra_params={
                                                        "WINDOWS_REGISTRY_1": test_regs[0],
                                                        "WINDOWS_REGISTRY_2": test_regs[1],
                                                        "FILE_SIZE_ENABLED": "yes",
                                                        "FILE_SIZE_LIMIT": "10KB",
                                                        "DISK_QUOTA_ENABLED": "yes",
                                                        "DISK_QUOTA_LIMIT": "1KB",
                                                        })

configurations_path = os.path.join(test_data_path, "wazuh_registry_report_changes_limits_quota.yaml")
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

# Fixtures


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize("size", [(8192), (32768)])
@pytest.mark.parametrize("key, subkey, arch, value_name",
                         [(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, KEY_WOW64_64KEY, "some_value"),
                          (WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, KEY_WOW64_32KEY, "some_value"),
                          (WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY_2, KEY_WOW64_64KEY, "some_value"), ],)
def test_disk_quota_values(key, subkey, arch, value_name, size, get_configuration, configure_environment,
                           restart_syscheckd, wait_for_fim_start):
    """
    description: Check if the 'wazuh-syscheckd' daemon sets the 'disk_quota' limit to be equal to the
                 'file_size' limit when it is enabled and it is bigger than the value given to 'disk_quota'
                 For this purpose, the test will monitor a key, create a testing value smaller than the
                 'disk_quota' limit, and increase its size on each test case. Finally, the test will verify
                 that the compressed diff file has been created, and the related FIM event includes the
                 'content_changes' field if the value size does not exceed the specified limit.
                 - Case 1, File size smaller than size_limit - tests that disk_quota is higher than the one originally
                   configured.
                 - Case 2, File size bigger than size_limit - tests that disk_quota does not allow for compressed files
                   bigger than size_limit (that is the value actually applied to disk_quota as well).

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: The registry key being monitored by syscheck.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value_name:
            type: str
            brief: Name of the testing value that will be created
        - size:
            type: int
            brief: Size of the content to write in the testing value.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the Wazuh logs file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that a 'diff' file is created when a monitored value does not exceed the size limit.
        - Verify that no 'diff' file is created when a monitored value exceeds the size limit.
        - Verify that FIM events include the 'content_changes' field when the monitored value
          does not exceed the size limit.

    input_description: A test case (test_limits) is contained in external YAML file
                       (wazuh_registry_report_changes_limits_quota.yaml) which includes configuration
                       settings for the 'wazuh-syscheckd' daemon. That is combined with
                       the testing registry keys to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - scheduled
    """
    values = create_values_content(value_name, size)

    _, diff_file = calculate_registry_diff_paths(key, subkey, arch, value_name)

    def report_changes_validator_no_diff(event):
        """Validate content_changes attribute does not exist in the event"""
        assert event["data"].get("content_changes") is None, ERR_MSG_CONTENT_CHANGES_NOT_EMPTY

    def report_changes_validator_diff(event):
        """Validate content_changes attribute exists in the event"""
        assert os.path.exists(diff_file), "{diff_file} does not exist"
        assert event["data"].get("content_changes") is not None, ERR_MSG_CONTENT_CHANGES_EMPTY

    if size > SIZE_LIMIT_CONFIGURED_VALUE:
        test_callback = report_changes_validator_no_diff
    else:
        test_callback = report_changes_validator_diff

    # Create the value inside the key - we do it here because it key or arch is not known before the test launches
    registry_value_create(key, subkey, wazuh_log_monitor, arch=arch, value_list=values, wait_for_scan=True,
                          scan_delay=scan_delay, min_timeout=global_parameters.default_timeout, triggers_event=True)
    # Modify the value to check if the diff file is generated or not, as expected
    registry_value_update(key, subkey, wazuh_log_monitor, arch=arch, value_list=values, wait_for_scan=True,
                          scan_delay=scan_delay, min_timeout=global_parameters.default_timeout, triggers_event=True,
                          validators_after_update=[test_callback])
    # Delete the value created to clean up enviroment
    registry_value_delete(key, subkey, wazuh_log_monitor, arch=arch, value_list=values, wait_for_scan=True,
                          scan_delay=scan_delay, min_timeout=global_parameters.default_timeout, triggers_event=True)
