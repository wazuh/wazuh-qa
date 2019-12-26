# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_registry, modify_registry, delete_registry, \
    check_time_travel, EventChecker, DEFAULT_TIMEOUT
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations

if sys.platform == 'win32':
    import winreg


# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

test_directories = []
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
monitoring_modes = ['scheduled']

sub_key = r'SOFTWARE\\Classes\\testkey'

# Configurations

conf_params, conf_metadata = generate_params(modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def extra_configuration_before_yield():
    # It makes sure to delete the registry if it already exists.
    try:
        delete_registry(winreg.HKEY_LOCAL_MACHINE, sub_key)
    except OSError:
        pass


@pytest.mark.parametrize('arch, tag, tags_to_apply', [
    (None, None, {'ossec_conf'}),
    ("64", None, {'ossec_conf_arch64'}),
    (None, "test_tag", {'ossec_conf_tag'})
])
def test_windows_registry(arch, tag, tags_to_apply,
                          get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check the correct monitoring of Windows Registries.

    This test creates a new registry in windows, adds a value, modifies
    it and then deletes the registry. It verifies that syscheck correctly monitors
    certain events while applying different settings.

    This test is intended to be used with valid configurations files. Each execution of this test will configure the
    environment properly, restart the service and wait for the initial scan.

    Parameters
    ----------
    arch : string
        Selected architecture
    tag : string
        Name of the tag to look for in the event
    tags_to_apply : set
         Run test if matches with a configuration identifier, skip otherwise
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])
    is_scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    event_checker = EventChecker(wazuh_log_monitor, folder=None)

    # Check that windows_registry does not trigger alerts for new entries and empty keys
    create_registry(winreg.HKEY_LOCAL_MACHINE, sub_key)
    check_time_travel(is_scheduled)
    event_checker.fetch_events(min_timeout=DEFAULT_TIMEOUT, triggers_event=False)

    # Check that windows_registry trigger alerts when adding an entry
    modify_registry(winreg.HKEY_LOCAL_MACHINE, sub_key, 'test_add')
    check_time_travel(is_scheduled)
    event = event_checker.fetch_events(min_timeout=DEFAULT_TIMEOUT, triggers_event=True)[0]
    assert event['data']['type'] == 'added', f'Event type not equal'

    # Check that windows_registry trigger alerts when modifying existing keys
    # and check arch and tag values match with the ones in event
    modify_registry(winreg.HKEY_LOCAL_MACHINE, sub_key, 'test_modify')
    check_time_travel(is_scheduled)
    event = event_checker.fetch_events(min_timeout=DEFAULT_TIMEOUT, triggers_event=True)[0]
    assert event['data']['type'] == 'modified', f'Event type not equal'
    if arch:
        assert arch in event['data']['path'], f'Architecture is not correct'
    if tag:
        assert event['data']['tags'] == tag, f'{tag} not found in event'

    # Check that windows_registry trigger alerts when deleting a key
    delete_registry(winreg.HKEY_LOCAL_MACHINE, sub_key)
    check_time_travel(is_scheduled)
    event = event_checker.fetch_events(min_timeout=DEFAULT_TIMEOUT, triggers_event=True)[0]
    assert event['data']['type'] == 'deleted', f'Event type not equal'
