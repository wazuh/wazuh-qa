# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
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


@pytest.mark.parametrize('tags_to_apply', [
    ({'multiple_keys'})
])
def test_multiple_keys(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """
    Check if FIM can detect every event when adding, modifying and deleting a subkey/value within multiple registry
    keys monitored in the same line.

    Only the first 64 registry keys should be monitored.

    These registry keys will be added in one single entry like this one:
        &lt;windows_registry&gt;testkey0, testkey1, ..., testkeyn&lt;/windows_registry&gt;
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    discarded = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_max_registry_monitored,
                                        error_message='Did not receive expected '
                                        '"Maximum number of registries to be monitored..." event.').result()

    assert discarded == expected_discarded, f'Discarded registry keys are not the expected ones.'

    detect_initial_scan(wazuh_log_monitor)  # Registry scan only works in scheduled mode

    multiple_keys_and_entries_keys(MAX_MONITORED_ONE_TAG, subkeys, wazuh_log_monitor, KEY,
                                   timeout=global_parameters.default_timeout)
    time.sleep(2)   # These 2 seconds are needed to avoid overlapping between keys and values
    multiple_keys_and_entries_values(MAX_MONITORED_ONE_TAG, subkeys, wazuh_log_monitor, KEY,
                                     timeout=global_parameters.default_timeout)
