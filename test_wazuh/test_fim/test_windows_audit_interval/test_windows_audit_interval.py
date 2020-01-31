# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import re

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

if sys.platform == 'win32':
    from test_fim.test_windows_audit_interval.manage_acl import Privilege, get_file_security_descriptor, modify_sacl, \
        get_sacl

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables

test_directories = [os.path.join(PREFIX, 'testdir_modify_sacl'), os.path.join(PREFIX, 'testdir_restore_sacl')]

directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir_modify, testdir_restore = test_directories
WAZUH_RULES = {'DELETE', 'WRITE_DAC', 'FILE_WRITE_DATA', 'FILE_WRITE_ATTRIBUTES'}
previous_rules = set()

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

windows_audit_interval = 20
conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': directory_str,
                                                           'WINDOWS_AUDIT_INTERVAL': str(windows_audit_interval)},
                                             modes=['whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions
def extra_configuration_before_yield():
    """Get list of SACL before Wazuh applies its own rules based on whodata monitoring."""
    with Privilege('SeSecurityPrivilege'):
        lfss = get_file_security_descriptor(testdir_restore)
        setattr(sys.modules[__name__], 'previous_rules', get_sacl(lfss))


def callback_sacl_changed(line):
    match = re.match(r".*The SACL of \'(.+)\' has been modified and it is not valid for the real-time Whodata mode. "
                     r"Whodata will not be available for this file.", line)
    if match:
        return match.group(1)


def callback_sacl_restored(line):
    match = re.match(r".*The SACL of \'(.+)\' has been restored correctly.", line)
    if match:
        return match.group(1)


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'audit_interval'}
])
def test_windows_audit_modify_sacl(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_initial_scan):
    """Check that Wazuh detects a SACL change every 'windows_audit_interval' and sets monitoring to real-time if so."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    with Privilege('SeSecurityPrivilege'):
        # Assert that Wazuh rules are added
        lfss = get_file_security_descriptor(testdir_modify)
        dir_rules = get_sacl(lfss)
        for rule in WAZUH_RULES:
            assert rule in dir_rules, f'{rule} not found in {dir_rules}'

        # Delete one of them and assert that after the 'windows_audit_interval' thread, Wazuh is set to real-time
        # monitoring
        modify_sacl(lfss, 'delete', mask=next(iter(WAZUH_RULES)))
        dir_rules = get_sacl(lfss)
        assert next(iter(WAZUH_RULES)) not in dir_rules

    event = wazuh_log_monitor.start(timeout=windows_audit_interval, callback=callback_sacl_changed).result()
    assert testdir_modify in event, f'{testdir_modify} not detected in SACL modification event'


@pytest.mark.parametrize('tags_to_apply', [
    {'audit_interval'}
])
def test_windows_audit_restore_sacl(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                    wait_for_initial_scan):
    """Check that Wazuh restores previous SACL rules when the service is stopped."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    with Privilege('SeSecurityPrivilege'):
        lfss = get_file_security_descriptor(testdir_restore)
        dir_rules = set(get_sacl(lfss))
        assert dir_rules - previous_rules == WAZUH_RULES

        # Stop Wazuh service to force SACL rules to be restored
        control_service('stop')
        event = wazuh_log_monitor.start(timeout=5, callback=callback_sacl_restored).result()
        assert testdir_restore in event, f'{testdir_restore} not detected in SACL restore event'
        dir_rules = set(get_sacl(lfss))
        assert dir_rules == previous_rules

    # Start Wazuh service again so the fixture does not crash
    control_service('start')
