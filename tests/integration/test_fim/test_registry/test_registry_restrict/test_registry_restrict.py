# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, create_registry, modify_registry_value, registry_parser, KEY_WOW64_32KEY, \
    KEY_WOW64_64KEY, callback_restricted, generate_params, callback_detect_event, delete_registry_value, \
    check_time_travel, delete_registry, REG_SZ
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables
key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\Classes\\testkey"
sub_key_2 = "SOFTWARE\\testkey"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2)]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1, reg2 = test_regs

valid_subkey = "key_restrict"
valid_value_name = "value_restrict"
no_valid_subkey = "some_key"
no_valid_value_name = "some_value"

# Configurations
conf_params = {'WINDOWS_REGISTRY_1': reg1,
               'WINDOWS_REGISTRY_2': reg2,
               'RESTRICT_VALUE': 'value_restrict$',
               'RESTRICT_KEY': 'key_restrict$'}

configurations_path = os.path.join(test_data_path, 'wazuh_restrict_conf.yaml')
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('key, subkey, arch, value_name, triggers_event, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, valid_value_name, True, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_32KEY, valid_value_name, True, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_64KEY, valid_value_name, True, {'value_restrict'}),
    (key, sub_key_1, KEY_WOW64_64KEY, no_valid_value_name, False, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_32KEY, no_valid_value_name, False, {'value_restrict'}),
    (key, sub_key_2, KEY_WOW64_64KEY, no_valid_value_name, False, {'value_restrict'})
])
def test_restrict_value(key, subkey, arch, value_name, triggers_event, tags_to_apply,
                        get_configuration, configure_environment, restart_syscheckd,
                        wait_for_fim_start):
    """
    Check the only registry values detected are those matching the restrict regex

    Parameters
    ----------
    key : str
        Root key (HKEY_*)
    subkey : str
        path of the registry.
    arch : str
        Architecture of the registry.
    value_name : str
        Name of the value that will be created
    triggers_event : bool
        True if an event must be generated, False otherwise.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    # This shouldn't create an alert because the key is already created
    key_h = create_registry(registry_parser[key], subkey, arch)
    # Create values
    modify_registry_value(key_h, value_name, REG_SZ, "added")
    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)

    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event, accum_results=2 if triggers_event else 1).result()

    if triggers_event:
        assert event[0]['data']['type'] == 'modified', 'Key event not modified'
        assert event[0]['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event[0]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        assert event[1]['data']['type'] == 'added', 'Event type not equal'
        assert event[1]['data']['path'] == os.path.join(key, subkey), 'Event path not equal'
        assert event[1]['data']['value_name'] == value_name, 'Value name not equal'
        assert event[1]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Value event arch not equal'
    else:
        assert event['data']['type'] == 'modified', 'Key event not modified'
        assert event['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        while True:
            ignored_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                    callback=callback_restricted,
                                                    error_message='Did not receive expected '
                                                                  '"Sending FIM event: ..." event').result()
            if ignored_value == value_name:
                break

    delete_registry_value(key_h, value_name)
    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event, accum_results=2 if triggers_event else 1).result()

    if triggers_event:
        assert event[0]['data']['type'] == 'modified', 'Key event not modified'
        assert event[0]['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event[0]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        assert event[1]['data']['type'] == 'deleted', 'Event type not equal'
        assert event[1]['data']['path'] == os.path.join(key, subkey), 'Event path not equal'
        assert event[1]['data']['value_name'] == value_name, 'Value name not equal'
        assert event[1]['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Value event arch not equal'
    else:
        # After deleting the value, we don't expect any message of the value because it's not in the DB
        assert event['data']['type'] == 'modified', 'Key event not modified'
        assert event['data']['path'] == os.path.join(key, subkey), 'Key event wrong path'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'


@pytest.mark.parametrize('key, subkey, test_subkey, arch, triggers_event, tags_to_apply', [
    (key, sub_key_1, valid_subkey, KEY_WOW64_64KEY, True, {'key_restrict'}),
    (key, sub_key_2, valid_subkey, KEY_WOW64_64KEY, True, {'key_restrict'}),
    (key, sub_key_2, valid_subkey, KEY_WOW64_32KEY, True, {'key_restrict'}),
    (key, sub_key_1, no_valid_subkey, KEY_WOW64_64KEY, False, {'key_restrict'}),
    (key, sub_key_2, no_valid_subkey, KEY_WOW64_64KEY, False, {'key_restrict'}),
    (key, sub_key_2, no_valid_subkey, KEY_WOW64_32KEY, False, {'key_restrict'})
])
def test_restrict_key(key, subkey, test_subkey, arch, triggers_event, tags_to_apply,
                      get_configuration, configure_environment, restart_syscheckd,
                      wait_for_fim_start):
    """
    Check the only registry keys detected are those matching the restrict regex

    Parameters
    ----------
    key : str
        Root key (HKEY_*)
    subkey : str
        Path of the registry.
    test_subkey : str
        Name of the key that will be used for the test
    arch : str
        Architecture of the registry.
    triggers_event : bool
        True if an event must be generated, False otherwise.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    test_key = os.path.join(subkey, test_subkey)
    create_registry(registry_parser[key], test_key, arch)

    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event, accum_results=1).result()
        assert event['data']['type'] == 'added', 'Event type not equal'
        assert event['data']['path'] == os.path.join(key, test_key), 'Event path not equal'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Arch not equal'

    else:
        while True:
            ignored_key = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_restricted,
                                                  error_message='Did not receive expected '
                                                                '"Sending FIM event: ..." event').result()
            if ignored_key == os.path.join(key, subkey):
                break

    delete_registry(registry_parser[key], test_key, arch)
    # Go ahead in time to let syscheck perform a new scan
    check_time_travel(get_configuration['metadata']['fim_mode'] == 'scheduled', monitor=wazuh_log_monitor)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event, accum_results=1).result()

        assert event['data']['type'] == 'deleted', 'key event not equal'
        assert event['data']['path'] == os.path.join(key, test_key), 'Key event wrong path'
        assert event['data']['arch'] == '[x32]' if arch == KEY_WOW64_32KEY else '[x64]', 'Key arch not equal'
