'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if the modifications made on registry
       entries during the initial scan ('baseline') generate FIM events before the scan is finished.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_basic_usage

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#windows-registry

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_basic_usage
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_detect_event, \
    modify_registry_value, callback_detect_end_scan, registry_parser, create_registry, KEY_WOW64_64KEY, \
    KEY_WOW64_32KEY, REG_SZ
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\testkey"

test_regs = [os.path.join(key, sub_key_1), os.path.join(key, sub_key_2)]
registry_str = ",".join(test_regs)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
reg1, reg2 = test_regs

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1, 'WINDOWS_REGISTRY_2': reg2}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_registry_both.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

registry_list = [(key, sub_key_1, KEY_WOW64_64KEY),
                 (key, sub_key_2, KEY_WOW64_32KEY),
                 (key, sub_key_2, KEY_WOW64_64KEY)]


# fixtures

@pytest.fixture(scope='function')
def restart_syscheckd_each_time(request):
    control_service('stop', daemon='wazuh-syscheckd')
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon='wazuh-syscheckd')


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def callback_detect_event_before_end_scan(line):
    ended_scan = callback_detect_end_scan(line)
    if ended_scan is None:
        event = callback_detect_event(line)
        assert event is None, 'Event detected before end scan'
        return None
    else:
        return True


@pytest.mark.parametrize('key, subkey, arch, value_type, content', [
    (key, sub_key_1, KEY_WOW64_64KEY, REG_SZ, 'added'),
    (key, sub_key_2, KEY_WOW64_32KEY, REG_SZ, 'added'),
    (key, sub_key_2, KEY_WOW64_64KEY, REG_SZ, 'added')
])
def test_wait_until_baseline(key, subkey, arch, value_type, content, get_configuration,
                             configure_environment, restart_syscheckd_each_time):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects registry events generated after the 'baseline'.
                 The log message 'File integrity monitoring scan ended' informs about the end of the first scan,
                 which generates that 'baseline'. For this purpose, the test will make key/value operations while
                 the initial scan is being performed. When the 'baseline' has been generated, it will verify that
                 the FIM events have been triggered.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: Path of the key that will be created under the root key.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value_type:
            type: srt
            brief: Type of the registry value to be created.
        - content:
            type: srt
            brief: Content of the registry value.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd_each_time:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor in each test case.

    assertions:
        - Verify that FIM events are generated during the initial scan for the changes detected
          on the monitored registry entries.

    input_description: A test case (ossec_conf_2) is contained in an external YAML file
                       (wazuh_conf_registry_both.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - scheduled
        - time_travel
    '''
    key_handle = create_registry(registry_parser[key], subkey, arch)

    modify_registry_value(key_handle, "value_name", value_type, content)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event_before_end_scan,
                            error_message='Did not receive expected event before end the scan')
