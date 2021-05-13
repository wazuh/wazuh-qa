# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
import wazuh_testing.fim as fim
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\Classes\\Testkey"

registry_1, registry_2 = os.path.join(key, sub_key_1), os.path.join(key, sub_key_2)
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_DUPLICATED_REGISTRY_1': registry_1,
               'WINDOWS_DUPLICATED_REGISTRY_2': registry_2}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_duplicated_registry.yaml')
parameters, metadata = fim.generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters, metadata=metadata)

registry_list = [(key, sub_key_1, fim.KEY_WOW64_32KEY), (key, sub_key_2,
                 fim.KEY_WOW64_32KEY)]


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# test
@pytest.mark.parametrize('key, subkey1, subkey2, arch', [(key, sub_key_1, sub_key_2,
                         fim.KEY_WOW64_32KEY)])
def test_registry_duplicated_entry(key, subkey1, subkey2, arch,
                                   get_configuration, configure_environment,
                                   restart_syscheckd, wait_for_fim_start):
    """Two registries with capital differences must trigger just one modify event

    Test to check that two registries monitored with the same name but
    capital differences only triggers one modified event when the registry is changed.


    Params:
        key (str): Name of the root subpath for registries.
        subkey1 (str): Name of the subpath identifying the registry 1 (no capital letter in name).
        subkey2 (str): Name of the subpath identifying the registry 2 (capital letter in name).
        arch (str): Value holding the system architecture for registries.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event (registry modified) couldn't be captured.
    """
    mode = get_configuration['metadata']['fim_mode']
    scheduled = mode == 'scheduled'

    registry_1 = fim.create_registry(fim.registry_parser[key], subkey1, arch)
    fim.create_registry(fim.registry_parser[key], subkey2, arch)

    fim.modify_registry_value(registry_1, "testkey", fim.REG_SZ, "some content x2")

    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=fim.callback_detect_modified_event,
                            error_message='Did not receive expected '
                            '"Sending Fim event: ..." event').result()

    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=fim.callback_detect_modified_event,
                                error_message='Did not receive expected '
                                '"Sending Fim event: ..." event').result()
        raise AttributeError('Only one modification event was expected.')
