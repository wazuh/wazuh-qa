# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import timedelta

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_ignore, create_registry, delete_registry
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine

if sys.platform == 'win32':
    import winreg

    keys = [(winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")]
else:
    keys = []

# All tests in this module apply to windows only
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_win32_ignore_registry.yaml')

keys_objects = list()
keys_strings = list()

for key in keys:
    object_, string_ = key
    keys_objects.append(object_)
    keys_strings.append(string_)

regs = [os.path.join('SOFTWARE', 'test'), os.path.join('SOFTWARE', 'test2')]
sub_keys = [os.path.join(regs[0], 'testreg32'), os.path.join(regs[0], 'testreg64'),
            os.path.join(regs[1], 'testregboth_32'), os.path.join(regs[1], 'testregboth_64')]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


def extra_configuration_before_yield():
    """ Initialize registries for this test """
    reg_handlers = list()
    for reg in regs:
        create_registry(keys_objects[0], reg, winreg.KEY_WOW64_32KEY | winreg.KEY_WRITE)
        create_registry(keys_objects[0], reg, winreg.KEY_WOW64_64KEY | winreg.KEY_WRITE)

    create_registry(keys_objects[0], sub_keys[0], winreg.KEY_WOW64_32KEY | winreg.KEY_WRITE)
    create_registry(keys_objects[0], sub_keys[1], winreg.KEY_WOW64_64KEY | winreg.KEY_WRITE)
    create_registry(keys_objects[0], sub_keys[2], winreg.KEY_WOW64_32KEY | winreg.KEY_WRITE)
    create_registry(keys_objects[0], sub_keys[3], winreg.KEY_WOW64_64KEY | winreg.KEY_WRITE)


def extra_configuration_after_yield():
    delete_registry(keys_objects[0], sub_keys[0], winreg.KEY_WOW64_32KEY)
    delete_registry(keys_objects[0], sub_keys[1], winreg.KEY_WOW64_64KEY)
    delete_registry(keys_objects[0], sub_keys[2], winreg.KEY_WOW64_32KEY)
    delete_registry(keys_objects[0], sub_keys[3], winreg.KEY_WOW64_64KEY)

    for reg in regs:
        delete_registry(keys_objects[0], reg, winreg.KEY_WOW64_32KEY)
        delete_registry(keys_objects[0], reg, winreg.KEY_WOW64_64KEY)


# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('key_string, key_object, tags_to_apply', [
    (keys_strings, keys_objects, {'ignore_registry'})
])
def test_ignore_registry(key_string, key_object, tags_to_apply, get_configuration,
                         configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Check registries are ignored according to configuration.

    Parameters
    ----------
    key_string : str
        String name of the key.
    key_object : object
        Object winreg of the key.
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    TimeMachine.travel_to_future(timedelta(hours=13))

    ignored_registry = wazuh_log_monitor.start(timeout=10, callback=callback_ignore,
                                               accum_results=len(sub_keys),
                                               error_message='Did not receive expected '
                                                             '"Ignoring ... due to( sregex)?" event').result()
    ignored_registry = set(ignored_registry)
    for ign_reg in sub_keys:
        try:
            ignored_registry.remove(os.path.join(keys_strings[0], ign_reg))
        except KeyError:
            raise KeyError(f'{os.path.join(keys_strings[0], ign_reg)} not in {ignored_registry}')
    assert len(ignored_registry) == 0
