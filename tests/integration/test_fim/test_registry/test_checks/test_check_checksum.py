# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import CHECK_SHA256SUM, CHECK_SHA1SUM, CHECK_MD5SUM, CHECK_SUM, CHECK_ALL, CHECK_TYPE, \
                              CHECK_SIZE, LOG_FILE_PATH, REQUIRED_REG_VALUE_ATTRIBUTES, \
                              generate_params, registry_value_cud, registry_key_cud

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\testkey1"
sub_key_2 = "SOFTWARE\\testkey2"
sub_key_3 = "SOFTWARE\\testkey3"
sub_key_4 = "SOFTWARE\\testkey4"


test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2),
             os.path.join(key, sub_key_3),
             os.path.join(key, sub_key_4)
             ]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

value_all_attrs = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL]
value_attrs = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL] - {CHECK_TYPE} - {CHECK_SIZE}

params_list_all = [(key, sub_key_1, value_all_attrs - REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM]),
                   (key, sub_key_2, value_all_attrs - {CHECK_MD5SUM} - {CHECK_SHA256SUM}),
                   (key, sub_key_3, value_all_attrs - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
                   (key, sub_key_4, value_all_attrs - {CHECK_SHA256SUM} - {CHECK_SHA1SUM}),
                   ]

params_list = [(key, sub_key_1, value_attrs - REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_SUM]),
               (key, sub_key_2, value_attrs - {CHECK_MD5SUM} - {CHECK_SHA256SUM}),
               (key, sub_key_3, value_attrs - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
               (key, sub_key_4, value_attrs - {CHECK_SHA256SUM} - {CHECK_SHA1SUM}),
               ]
# Configurations

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'WINDOWS_REGISTRY_3': test_regs[2],
               'WINDOWS_REGISTRY_4': test_regs[3]
               }

configurations_path = os.path.join(test_data_path, 'wazuh_check_checksum.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


@pytest.mark.parametrize('key, subkey, value_attr', params_list_all)
def test_check_checksum_all(key, subkey, value_attr,
                            get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Test the behaviour disabling different check options over the same key with check_all enabled

    Example:
        check_all: "yes" check_size: "no" check_sum: "no"

    Parameters
    ----------
    key: str
        Key of the registry (HKEY_* constants)
    subkey: str
        Path of the subkey.
    value_attr: set
        Set of options that are expected for value events
    """
    check_apply_test({'test_checksum_all'}, get_configuration['tags'])
    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=15,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=15, options=value_attr,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


@pytest.mark.parametrize('key, subkey, value_attr', params_list)
def test_check_checksum(key, subkey, value_attr,
                        get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Test the behaviour disabling different check options over the same key with check_all enabled

    Example:
        check_all: "yes" check_size: "no" check_sum: "no"

    Parameterskey_attr
        Path of the subkey.
    key_attr: set
        Set of options that are expected for key events
    value_attr: set
        Set of options that are expected for value events
    triggers_value_modification: boolean
        Specify if value modification events are going to be triggered
    """
    check_apply_test({'test_checksum'}, get_configuration['tags'])
    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, min_timeout=15,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

    # Test registry values.
    registry_value_cud(key, subkey, wazuh_log_monitor, min_timeout=15, options=value_attr,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
