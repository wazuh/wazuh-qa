'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will verify that FIM does not limit the size of the key
       monitored to generate 'diff' information or the 'queue/diff/local' folder where Wazuh stores the
       compressed files used to perform the 'diff' operation. Having the 'file_size' and 'disk_quota'
       options disabled, and the 'report_changes' option enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#diff

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
'''
import os

import pytest
from test_fim.test_files.test_report_changes.common import generate_string
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params, \
    calculate_registry_diff_paths
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\test_key"
sub_key_2 = "SOFTWARE\\Classes\\test_key"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2)]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1, reg2 = test_regs
size_limit_configured = 10 * 1024

# Configurations

p, m = generate_params(modes=['scheduled'], extra_params={'WINDOWS_REGISTRY_1': reg1,
                                                          'WINDOWS_REGISTRY_2': reg2,
                                                          'FILE_SIZE_ENABLED': 'no',
                                                          'FILE_SIZE_LIMIT': '10KB',
                                                          'DISK_QUOTA_ENABLED': 'no',
                                                          'DISK_QUOTA_LIMIT': '4KB'})

configurations_path = os.path.join(test_data_path, 'wazuh_registry_report_changes_limits_quota.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('key, subkey, arch, value_name, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", {'test_limits'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", {'test_limits'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", {'test_limits'})
])
def test_all_limits_disabled(key, subkey, arch, value_name, tags_to_apply,
                             get_configuration, configure_environment, restart_syscheckd,
                             wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates all FIM events when the 'file_size' and
                 the 'disk_quota' tags have set a small limit but they are disabled. For this purpose,
                 the test will monitor a key and create multiple values with a content of big size inside it.
                 That values exceed both, 'file_size' and 'disk_quota' limits. Finally, the test will verify
                 that all FIM events have been generated, since that those limits are disabled.

    wazuh_min_version: 4.2.0

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
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that all FIM events are generated for the modifications made on the testing values.
        - Verify that a 'diff' file is created for each monitored value.
        - Verify that FIM events include the 'content_changes' field.

    input_description: A test case (test_limits) is contained in external YAML file
                       (wazuh_registry_report_changes_limits_quota.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon. That is
                       combined with the testing registry keys to be monitored defined
                       in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    value_content = generate_string(4 * 1024 * 1024, '0')
    values = {value_name: value_content}

    _, diff_file = calculate_registry_diff_paths(key, subkey, arch, value_name)

    def report_changes_validator_diff(event):
        """Validate content_changes attribute exists in the event"""
        assert os.path.exists(diff_file), '{diff_file} does not exist'
        assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=values,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout, triggers_event=True,
                       validators_after_update=[report_changes_validator_diff])
