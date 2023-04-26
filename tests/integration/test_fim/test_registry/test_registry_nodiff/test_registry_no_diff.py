'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM ignores the modifications made
       in a monitored value when it matches the 'registry_nodiff' tag and vice versa.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_nodiff

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#registry-nodiff

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_nodiff
'''
import os
import sys
from hashlib import sha1
from time import sleep

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\test_key"
sub_key_2 = "SOFTWARE\\Classes\\test_key"
no_diff_value = "nodiff_value"
value_sregex = "nodiff_value$"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2)]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1, reg2 = test_regs

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1,
               'WINDOWS_REGISTRY_2': reg2,
               'VALUE_1': os.path.join(reg1, no_diff_value),
               'VALUE_2': os.path.join(reg2, no_diff_value),
               'SREGEX_1': value_sregex,
               'SREGEX_2': value_sregex}

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key, subkey, arch, value_name, truncated, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_str'}),
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", False, {'no_diff_str'}),
    (key, sub_key_1, KEY_WOW64_32KEY, no_diff_value, True, {'no_diff_str'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", False, {'no_diff_str'}),
    (key, sub_key_2, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_str'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", False, {'no_diff_str'})

])
def test_no_diff_str(key, subkey, arch, value_name, truncated, tags_to_apply,
                     get_configuration, configure_environment, restart_syscheckd,
                     wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon truncates the value changes in the generated events using
                 the value path in the 'registry_nodiff' tag and vice versa. For this purpose, the test will monitor
                 a key and make value operations inside it. Then, it will check if the 'diff' file is created for
                 each testing value modified. Finally, if the testing values match the 'registry_nodiff' tag,
                 the test will verify that the FIM events generated contain in their 'content_changes' field
                 a message indicating that 'diff' is truncated because the 'nodiff' option is used.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: Path of the registry entry where the test will be executed.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value_name:
            type: str
            brief: Name of the value that will be created.
        - truncated:
            type: bool
            brief: True if an event must be generated, False otherwise.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that FIM ignores the modifications made in a monitored value
          when it matches the 'registry_nodiff' tag.
        - Verify that FIM includes the modifications made in a monitored value
          when it does not match the 'registry_nodiff' tag.

    input_description: A test case (no_diff_str) is contained in an external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is
                       combined with the testing registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    values = {value_name: "some content"}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for value in values:
            folder_str = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                        sha1(os.path.join(key, subkey).encode()).hexdigest())
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_str,
                                     sha1(value.encode()).hexdigest())

            assert os.path.exists(diff_file), '{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if truncated:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                'content_changes is truncated'

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=values,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout, triggers_event=True,
                       validators_after_update=[report_changes_validator, no_diff_validator])
    sleep(0.5)


@pytest.mark.parametrize('key, subkey, arch, value_name, truncated, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_regex'}),
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", False, {'no_diff_regex'}),
    (key, sub_key_1, KEY_WOW64_32KEY, no_diff_value, True, {'no_diff_regex'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", False, {'no_diff_regex'}),
    (key, sub_key_2, KEY_WOW64_64KEY, no_diff_value, True, {'no_diff_regex'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", False, {'no_diff_regex'})
])
def test_no_diff_regex(key, subkey, arch, value_name, truncated, tags_to_apply,
                       get_configuration, configure_environment, restart_syscheckd,
                       wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon truncates the value changes in the generated events using
                 regex in the 'registry_nodiff' tag and vice versa. For this purpose, the test will monitor
                 a key and make value operations inside it. Then, it will check if the 'diff' file is created for
                 each testing value modified. Finally, if the testing values match the 'registry_nodiff' tag,
                 the test will verify that the FIM events generated contain in their 'content_changes' field
                 a message indicating that 'diff' is truncated because the 'nodiff' option is used.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: Path of the registry entry where the test will be executed.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value_name:
            type: str
            brief: Name of the value that will be created.
        - truncated:
            type: bool
            brief: True if an event must be generated, False otherwise.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that FIM ignores the modifications made in a monitored value
          when it matches the 'registry_nodiff' tag.
        - Verify that FIM includes the modifications made in a monitored value
          when it does not match the 'registry_nodiff' tag.

    input_description: A test case (no_diff_regex) is contained in an external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is
                       combined with the testing registry keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    values = {value_name: "some content"}

    def report_changes_validator(event):
        """Validate content_changes attribute exists in the event"""
        for value in values:
            folder_str = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                        sha1(os.path.join(key, subkey).encode()).hexdigest())

            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_str,
                                     sha1(value.encode()).hexdigest())

            assert os.path.exists(diff_file), '{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, 'content_changes is empty'

    def no_diff_validator(event):
        """Validate content_changes value is truncated if the file is set to no_diff"""
        if truncated:
            assert '<Diff truncated because nodiff option>' in event['data'].get('content_changes'), \
                'content_changes is not truncated'
        else:
            assert '<Diff truncated because nodiff option>' not in event['data'].get('content_changes'), \
                'content_changes is truncated'

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=values,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout, triggers_event=True,
                       validators_after_update=[report_changes_validator, no_diff_validator])
    # Avoid overlapping of events
    sleep(0.5)
