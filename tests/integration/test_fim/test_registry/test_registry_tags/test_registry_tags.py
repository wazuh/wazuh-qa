'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM events include
       all tags set in the 'tags' attribute.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_tags

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
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, generate_params, KEY_WOW64_64KEY, KEY_WOW64_32KEY
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables
key = "HKEY_LOCAL_MACHINE"
sub_key = "SOFTWARE\\test_key"
sub_key_2 = "SOFTWARE\\Classes\\test_key"

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_regs = [os.path.join(key, sub_key), os.path.join(key, sub_key_2)]
reg1, reg2 = test_regs
# Configurations
tags = ['tag1', 'tág', '0tag', '000', 'a' * 1000]
conf_params = {'WINDOWS_REGISTRY_1': reg1, 'WINDOWS_REGISTRY_2': reg2}

configurations_path = os.path.join(test_data_path, 'wazuh_registry_tag_conf.yaml')
p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'FIM_TAGS': tag} for tag in tags),
                       modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('key, subkey, arch', [
    (key, sub_key, KEY_WOW64_32KEY),
    (key, sub_key, KEY_WOW64_64KEY),
    (key, sub_key_2, KEY_WOW64_64KEY)
])
def test_tags(key, subkey, arch,
              get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates the tags required for each event depending
                 on the values set in the 'tags' attribute. This attribute allows adding tags to alerts for
                 monitored registry entries. For this purpose, the test will monitor a key and make value
                 operations inside it. Finally, it will verify that FIM events generated include in the
                 'tags' field all tags set in the configuration.

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
        - Verify that FIM events include all tags set in the 'tags' attribute.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_registry_tag_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the testing registry keys to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    defined_tags = get_configuration['metadata']['fim_tags']

    def tag_validator(event):
        assert defined_tags == event['data']['tags'], f'defined_tags are not equal'

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout,
                       triggers_event=True,
                       validators_after_cud=[tag_validator]
                       )
