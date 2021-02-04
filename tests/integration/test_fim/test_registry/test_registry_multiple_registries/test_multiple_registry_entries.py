# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

from common import multiple_keys_and_entries_keys, multiple_keys_and_entries_values

# Marks


pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables


n_regs = 64
KEY = "HKEY_LOCAL_MACHINE"
subkeys = [os.path.join('SOFTWARE', 'Classes', f'testkey{i}') for i in range(n_regs)]
test_regs = [os.path.join(KEY, sub_key) for sub_key in subkeys]
registry_str = ",".join(test_regs)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_multiple_entries.yaml')

# Configurations


conf_params = {f'WINDOWS_REGISTRY{i}': testreg for i, testreg in enumerate(test_regs)}
conf_params['MODULE_NAME'] = __name__

p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test


@pytest.mark.parametrize('tags_to_apply', [
    ({'multiple_reg_entries'})
])
def test_multiple_entries(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                          wait_for_fim_start):
    """
    Check if syscheck can detect every event when adding, modifying and deleting a subkey/value within multiple
    monitored registry keys.

    These registry keys will be added using a new entry for every one of them:
        &lt;windows_registry&gt;testkey0&lt;/windows_registry&gt;
        ...
        &lt;windows_registry&gt;testkeyn&lt;/windows_registry&gt;
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    multiple_keys_and_entries_keys(n_regs, subkeys, wazuh_log_monitor, KEY, timeout=global_parameters.default_timeout)
    time.sleep(2)  # These 2 seconds are needed to avoid overlapping between keys and values
    multiple_keys_and_entries_values(n_regs, subkeys, wazuh_log_monitor, KEY, timeout=global_parameters.default_timeout)
