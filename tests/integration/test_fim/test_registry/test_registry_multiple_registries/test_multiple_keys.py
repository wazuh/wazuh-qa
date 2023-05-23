'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM detects all registry modification
       events when monitoring the maximum number of keys (64) set in the 'windows_registry' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_multiple_registries

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
    - fim_registry_multiple_registries
'''
import os
import sys
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_max_registry_monitored, detect_initial_scan
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

from common import multiple_keys_and_entries_keys, multiple_keys_and_entries_values

# Marks


pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables


n_regs = 70
MAX_MONITORED_ONE_TAG = 64  # Maximum number of monitored registry keys in one windows_registry tag
KEY = "HKEY_LOCAL_MACHINE"
subkeys = [os.path.join('SOFTWARE', 'Classes', f'testkey{i}') for i in range(n_regs)]
test_regs = [os.path.join(KEY, sub_key) for sub_key in subkeys]
registry_str = ",".join(test_regs)
expected_discarded = ','.join([os.path.join(KEY, subkeys[i]) for i in range(64, n_regs)])

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_multiple_keys.yaml')

# Configurations


conf_params = {'WINDOWS_REGISTRY': registry_str}
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.skipif(sys.platform=='win32', reason="Blocked by #4077.")
@pytest.mark.parametrize('tags_to_apply', [({'multiple_keys'})])
def test_multiple_keys(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects every event when adding, modifying, and deleting
                 a subkey/value within multiple registry keys monitored in the same line. Also, it verifies that
                 it limits the monitoring to the maximum allowed number of keys (64) set in the 'windows_registry'
                 tag. For this purpose, the test will try to monitor an upper number of keys allowed and verify
                 that FIM discards the excess of keys to monitor. Then, it will make key/value operations inside
                 of the monitored keys, and finally, the test will verify that all FIM events are generated for
                 the operations made.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
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

    assertions:
        - Verify that FIM 'discard' event is generated with the number of discarded keys to monitor.

    input_description: A test case (multiple_keys) is contained in external YAML file (wazuh_conf_multiple_keys.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined
                       with the testing registry key to be monitored defined in this module.

    expected_output:
        - r'.*Maximum number of registries to be monitored in the same tag reached .* Excess are discarded'
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    discarded = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_max_registry_monitored,
                                        error_message='Did not receive expected '
                                                      '"Maximum number of registries to be monitored..." event.'
                                        ).result()

    assert discarded == expected_discarded, f'Discarded registry keys are not the expected ones.'

    detect_initial_scan(wazuh_log_monitor)  # Registry scan only works in scheduled mode

    multiple_keys_and_entries_keys(MAX_MONITORED_ONE_TAG, subkeys, wazuh_log_monitor, KEY,
                                   timeout=global_parameters.default_timeout)
    time.sleep(2)  # These 2 seconds are needed to avoid overlapping between keys and values
    multiple_keys_and_entries_values(MAX_MONITORED_ONE_TAG, subkeys, wazuh_log_monitor, KEY,
                                     timeout=global_parameters.default_timeout)
