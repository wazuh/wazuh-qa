# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, \
    create_registry, registry_parser, registry_value_cud, KEY_WOW64_64KEY
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables
arch = KEY_WOW64_64KEY
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes"
for i in range(30):
    sub_key_1 += "\\"
    for j in range(255):
        sub_key_1 += "a"

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
reg1 = os.path.join(key, sub_key_1)

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_reg_attr.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def extra_configuration_before_yield():
    create_registry(registry_parser[key], sub_key_1, arch)


def test_long_registry_path(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if long key names generates events
    """

    max_value_name = "value_test"
    for i in range(16372):
        max_value_name += "a"

    registry_value_cud(key, sub_key_1, wazuh_log_monitor, arch=arch,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout,
                       triggers_event=True, value_list=[max_value_name])
