# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_registry, modify_registry, delete_registry, \
    timedelta, callback_detect_event
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine

if sys.platform == 'win32':
    import winreg

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

test_directories = []
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
monitoring_modes = ['scheduled']

sub_key = os.path.join('SOFTWARE', 'Classes', 'testkey')
registry = os.path.join('HKEY_LOCAL_MACHINE', sub_key)
frequency = 4

# Configurations

conf_params = {'WINDOWS_REGISTRY': registry, 'FREQUENCY': frequency}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_no_attr.yaml')
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations1 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

attributes = [{'arch': 'both'}, {'tags': 'test_tag'}]
configurations_path = os.path.join(test_data_path, 'wazuh_conf_attr.yaml')
p, m = generate_params(extra_params=conf_params, apply_to_all=({'ATTRIBUTE': attr} for attr in attributes),
                       modes=monitoring_modes)
configurations2 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

configurations = configurations1 + configurations2


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def extra_configuration_before_yield():
    # It makes sure to delete the registry if it already exists.
    try:
        delete_registry(winreg.HKEY_LOCAL_MACHINE, sub_key, winreg.KEY_WOW64_32KEY)
    except OSError:
        pass


@pytest.mark.parametrize('arch_list, tag, tags_to_apply', [
    (['32'], None, {'ossec_conf'}),
    (['32', '64'], None, {'ossec_conf_2'}),
    (['32'], "test_tag", {'ossec_conf_2'})
])
def test_windows_registry(arch_list, tag, tags_to_apply,
                          get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check the correct monitoring of Windows Registries.

    This test creates a new registry in windows, adds a value, modifies
    it and then deletes the registry. It verifies that syscheck correctly monitors
    certain events while applying different settings.

    Parameters
    ----------
    arch_list : list
        Selected architectures.
    tag : str
        Name of the tag to look for in the event.
    tags_to_apply : set
         Run test if matches with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Check that configuration is applying to the correct test
    if ((tag and 'tags' not in get_configuration['metadata']['attribute'].keys()) or
            (len(arch_list) > 1 and 'arch' not in get_configuration['metadata']['attribute'].keys())):
        pytest.skip("Does not apply to this config file")

    # Check that windows_registry does not trigger alerts for new keys
    create_registry(winreg.HKEY_LOCAL_MACHINE, sub_key, winreg.KEY_WOW64_32KEY | winreg.KEY_WRITE)
    TimeMachine.travel_to_future(timedelta(seconds=frequency))
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                error_message='Did not receive expected "Sending FIM event: ..." event',
                                accum_results=len(arch_list))

    # Check that windows_registry trigger alerts when adding an entry
    modify_registry(winreg.HKEY_LOCAL_MACHINE, sub_key, 'test_add')
    TimeMachine.travel_to_future(timedelta(seconds=frequency))
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                    error_message='Did not receive expected "Sending FIM event: ..." event',
                                    accum_results=len(arch_list)).result()
    if not isinstance(event, list):
        event = [event]
    for i, arch in enumerate(arch_list):
        assert event[i]['data']['type'] == 'added', f'Event type not equal'

    # Check that windows_registry trigger alerts when modifying existing entries
    # and check arch and tag values match with the ones in event
    modify_registry(winreg.HKEY_LOCAL_MACHINE, sub_key, 'test_modify')
    TimeMachine.travel_to_future(timedelta(seconds=frequency))
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                    error_message='Did not receive expected "Sending FIM event: ..." event',
                                    accum_results=len(arch_list)).result()
    if not isinstance(event, list):
        event = [event]
    for i, arch in enumerate(arch_list):
        assert event[i]['data']['type'] == 'modified', f'Event type not equal'
        if arch:
            assert arch in event[i]['data']['path'], f'Architecture is not correct'
        if tag:
            assert event[i]['data']['tags'] == tag, f'{tag} not found in event'

    # Check that windows_registry trigger alerts when deleting a key
    delete_registry(winreg.HKEY_LOCAL_MACHINE, sub_key, winreg.KEY_WOW64_32KEY)
    TimeMachine.travel_to_future(timedelta(seconds=frequency))
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                    error_message='Did not receive expected "Sending FIM event: ..." event',
                                    accum_results=len(arch_list)).result()
    if not isinstance(event, list):
        event = [event]
    for i, arch in enumerate(arch_list):
        assert event[i]['data']['type'] == 'deleted', f'{event[i]["data"]["type"]} type not equal to deleted'
