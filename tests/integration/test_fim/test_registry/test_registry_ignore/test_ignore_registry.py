# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters, fim
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
subkey_1 = "SOFTWARE\\test_key"
subkey_2 = "SOFTWARE\\Classes\\test_key"
ignore_key = "key_ignore"
ignore_regex = "ignored_key$"
ignore_value = "value_ignored"
ignore_value_regex = "ignored_value$"

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_regs = [os.path.join(key, subkey_1), os.path.join(key, subkey_2)]

reg1, reg2 = test_regs

# Configurations

conf_params = {'WINDOWS_REGISTRY_1': reg1,
               'WINDOWS_REGISTRY_2': reg2,
               'REGISTRY_IGNORE_1': os.path.join(reg1, ignore_key),
               'REGISTRY_IGNORE_2': os.path.join(reg2, ignore_key),
               'REGISTRY_IGNORE_REGEX': ignore_regex,
               'VALUE_IGNORE_1': os.path.join(reg1, ignore_value),
               'VALUE_IGNORE_2': os.path.join(reg2, ignore_value),
               'VALUE_IGNORE_REGEX': ignore_value_regex
               }
configurations_path = os.path.join(test_data_path, 'wazuh_registry_ignore_conf.yaml')
p, m = fim.generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


@pytest.fixture(scope='function')
def reset_registry_ignore_path():
    yield
    fim.registry_ignore_path = None


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('root_key, registry, arch, subkey, triggers_event, tags_to_apply', [
    (key, subkey_1, fim.KEY_WOW64_32KEY, "some_key", True, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "some_key", True, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, ignore_key, False, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, ignore_key, False, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "regex_ignored_key", False, {'ignore_registry_key'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, "regex_ignored_key", False, {'ignore_registry_key'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "some_key", True, {'ignore_registry_key'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, ignore_key, False, {'ignore_registry_key'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "regex_ignored_key", False, {'ignore_registry_key'})
])
@pytest.mark.skip(reason="It will be blocked by #1602, when it was solve we can enable again this test")
def test_ignore_registry_key(root_key, registry, arch, subkey, triggers_event, tags_to_apply,
                             get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start,
                             reset_registry_ignore_path):
    """
    Check registry keys are ignored according to configuration.

    Parameters
    ----------
    root_key : str
        Root key (HKEY_*)
    registry : str
        path of the registry where the test will be executed.
    arch : str
        Architecture of the registry.
    subkey : str
        Name of the key that will be created.
    triggers_event : bool
        True if an event must be generated, False otherwise.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    fim.registry_ignore_path = os.path.join(root_key, registry)

    # Create registry
    fim.create_registry(fim.registry_parser[root_key], os.path.join(registry, subkey), arch)
    # Go ahead in time to let syscheck perform a new scan
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=fim.callback_key_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        assert event['data']['type'] == 'added', 'Wrong event type.'
        assert event['data']['path'] == os.path.join(root_key, registry, subkey), 'Wrong key path.'
        assert event['data']['arch'] == '[x32]' if arch == fim.KEY_WOW64_32KEY else '[x64]', 'Wrong key arch.'

    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=fim.callback_key_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()


@pytest.mark.parametrize('root_key, registry, arch, value, triggers_event, tags_to_apply', [
    (key, subkey_1, fim.KEY_WOW64_32KEY, "some_value", True, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "some_value", True, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, "regex_ignored_value", False, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, "regex_ignored_value", False, {'ignore_registry_value'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "regex_ignored_value", False, {'ignore_registry_value'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, "some_value", True, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_32KEY, ignore_value, False, {'ignore_registry_value'}),
    (key, subkey_1, fim.KEY_WOW64_64KEY, ignore_value, False, {'ignore_registry_value'}),
    (key, subkey_2, fim.KEY_WOW64_64KEY, ignore_value, False, {'ignore_registry_value'})
])
@pytest.mark.skip(reason="It will be blocked by #1602, when it was solve we can enable again this test")
def test_ignore_registry_value(root_key, registry, arch, value, triggers_event, tags_to_apply,
                               get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check registry values are ignored according to configuration.

    Parameters
    ----------
    root_key : str
        Root key (HKEY_*)
    registry : str
        path of the registry where the test will be executed.
    arch : str
        Architecture of the registry.
    value : str
        Name of the value that will be created.
    triggers_event : bool
        True if an event must be generated, False otherwise.
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    # Open the key (this shouldn't create an alert)
    key_h = fim.create_registry(fim.registry_parser[root_key], registry, arch)
    # Create values
    fim.modify_registry_value(key_h, value, fim.REG_SZ, "test_value")
    # Go ahead in time to let syscheck perform a new scan
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)

    if triggers_event:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=fim.callback_value_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()

        assert event['data']['type'] == 'added', 'Wrong event type.'
        assert event['data']['path'] == os.path.join(root_key, registry), 'Wrong value path.'
        assert event['data']['arch'] == '[x32]' if arch == fim.KEY_WOW64_32KEY else '[x64]', 'wrong key arch.'
        assert event['data']['value_name'] == value, 'Wrong value name'

    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=fim.callback_value_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()
