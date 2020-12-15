# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, registry_value_cud, registry_key_cud, KEY_WOW64_64KEY, \
    KEY_WOW64_32KEY, REG_SZ, REG_MULTI_SZ, REG_DWORD
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

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

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('value_type', [
    REG_SZ,
    REG_MULTI_SZ,
    REG_DWORD
])
@pytest.mark.parametrize('key, subkey, arch', [
    (key, sub_key_1, KEY_WOW64_64KEY),
    (key, sub_key_2, KEY_WOW64_32KEY),
    (key, sub_key_2, KEY_WOW64_64KEY)
])
def test_registry_changes(key, subkey, arch, value_type, get_configuration, configure_environment, restart_syscheckd,
                          wait_for_fim_start):
    """
    Check if events appear for subkeys/values of a monitored key
    """
    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout,
                     triggers_event=True)

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout,
                       triggers_event=True, value_type=value_type)
