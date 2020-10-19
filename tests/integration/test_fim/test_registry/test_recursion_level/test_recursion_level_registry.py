# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
import sys

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_audit_event_too_long, registry_value_cud, delete_registry, \
    registry_parser, generate_params, registry_parser, create_registry

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from win32api import RegOpenKeyEx

import win32con
# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables
key = "HKEY_LOCAL_MACHINE"
registry = "SOFTWARE"
registry_no_recursion = os.path.join(registry, 'norecursion')
registry_recrusion_1 = os.path.join(registry, 'recursion1')
registry_recrusion_5 = os.path.join(registry, 'recursion5')
registry_recrusion_512 = os.path.join(registry, 'recursion512')

registry_list = [registry_no_recursion, registry_recrusion_1, registry_recrusion_5, registry_recrusion_512]
test_regs = [registry_no_recursion, registry_recrusion_1, registry_recrusion_5, registry_recrusion_512]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

# Configurations

configurations_path = os.path.join(test_data_path, "wazuh_recursion_windows_registry.yaml")
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

p, m = generate_params(apply_to_all=({'FIM_MODE' : 'scheduled'}))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

def extra_configuration_before_yield():
    """Make sure to delete any existing key with the same name before performing the test"""
    for reg_key in registry_list:
        create_registry(registry_parser[key], reg_key, 0, win32con.KEY_WOW64_32KEY)

def extra_configuration_after_yield():
    """Make sure to delete the key after performing the test"""
    for reg_key in registry_list:
        try:
            delete_registry(registry_parser[key], reg_key, 0, win32con.KEY_WOW64_32KEY)
        except win32api.error:
            pass
# Functions

def recursion_test(key, registry, subkey, recursion_level, timeout=1, edge_limit=2, ignored_levels=1, is_scheduled=False):
    """
    Check that events are generated in the first and last `edge_limit` directory levels in the hierarchy
    registry\\subregistry1\\subregistry2\\...\\subregistry{recursion_level}. It also checks that no events are generated for
    registry\\subregistry{recursion_level+ignored_levels}. All registry and dubkrud needed will be created using the info
    provided by parameter.

    Example:
        recursion_level = 10
        edge_limit = 2
        ignored_levels = 2

        registry = "HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key"
        subreg = "subkey"

        With those parameters this function will create keys/values and expect to detect 'added', 'modified' and 'deleted'
        events for the following registry only, as they are the first and last 2 subkeys within recursion
        level 10:

        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key1
        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key1\\subkey2
        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key1\\subkey2\\subkey3\\subkey4\\subkey5\\subkey6\\subkey7\\subkey8\\subkey9\\
        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key1\\subkey2\\subkey3\\subkey4\\subkey5\\subkey6\\subkey7\\subkey8\\subkey9\\subkey10

        As ignored_levels value is 2, this function will also create files on the following subkeys and ensure that
        no events are raised as they are outside the recursion level specified:

        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key1\\subkey2\\subkey3\\subkey4\\subkey5\\subkey6\\subkey7\\subkey8\\subkey9\\subkey10\\subkey11
        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key1\\subkey2\\subkey3\\subkey4\\subkey5\\subkey6\\subkey7\\subkey8\\subkey9\\subkey10\\subkey11\\subkey12

    Parameters
    ----------
    key : str
        Registry key **STRING** (HKEY_* constants)
    registry : str
        The registry key being monitored by syscheck (indicated in the .conf file without the HKEY_* constant).
    subkey : str
        The name of the subkeys that will be created during the execution for testing purposes.
    recursion_level : int
        Recursion level. Also used as the number of subkeys to be created and checked for the current test.
    timeout : int
        Max time to wait until an event is raised.
    edge_limit : int
        Number of subkeys where the test will monitor events.
    ignored_levels : int
        Number of subkeys exceeding the specified recursion_level to verify events are not raised.
    is_scheduled : bool
        If True the internal date will be modified to trigger scheduled checks by syschecks.
        False if realtime or Whodata.
    """
    key = registry_parser[key]
    path = key + registry
    try:
        # Check True (Within the specified recursion level)
        for n in range(recursion_level):
            path = os.path.join(path, subkey + str(n + 1))
            if ((recursion_level < edge_limit * 2) or
                    (recursion_level >= edge_limit * 2 and n < edge_limit) or
                    (recursion_level >= edge_limit * 2 and n > recursion_level - edge_limit)):
                registry_value_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout)

        # Check False (exceeding the specified recursion_level)
        for n in range(recursion_level, recursion_level + ignored_levels):
            path = os.path.join(path, subkey + str(n + 1))
            registry_value_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout,
                               triggers_event=False)

    except TimeoutError:
        timeout_log_monitor = FileMonitor(LOG_FILE_PATH)
        if timeout_log_monitor.start(timeout=5, callback=callback_audit_event_too_long).result():
            pytest.fail("Audit raised 'Event Too Long' message.")
        raise

    except FileNotFoundError as ex:
        MAX_PATH_LENGTH_WINDOWS_ERROR = 206
        if ex.winerror != MAX_PATH_LENGTH_WINDOWS_ERROR:
            raise

    except OSError as ex:
        MAX_PATH_LENGTH_MACOS_ERROR = 63
        MAX_PATH_LENGTH_SOLARIS_ERROR = 78
        if ex.errno not in (MAX_PATH_LENGTH_SOLARIS_ERROR, MAX_PATH_LENGTH_MACOS_ERROR):
            raise


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    return request.param


# Tests

@pytest.mark.parametrize('key, registry, subkey, recursion_level', [
    (key, registry_no_recursion, 'subkey', 0),
    (key, registry_recrusion_1, 'subkey', 1),
    (key, registry_recrusion_5, 'subkey', 5),
    (key, registry_recrusion_512, 'subkey', 512)
])
def test_recursion_level(key, registry, subkey, recursion_level, get_configuration, configure_environment,
                         restart_syscheckd, wait_for_initial_scan):
    """
    Check if files are correctly detected by syscheck with recursion level using scheduled, realtime and whodata
    monitoring.

    Parameters
    ----------
    key : str
        String with the key of the registry (HKEY_* constants)
    registry : str
        String with the registry that is monitored (without the key string).
    subkey : str
        Name that will be used to generate subkeys int the monitored registry
    recursion_level : int
        Recursion level. Also used as the number of subkeys to be created and checked for the current test.
    """
    recursion_test(key, registry, subkey, recursion_level, timeout=global_parameters.default_timeout,
                   is_scheduled=get_configuration['metadata']['fim_mode'] == 'scheduled')
