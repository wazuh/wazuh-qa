# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, registry_parser, generate_params, \
     create_registry, KEY_WOW64_64KEY

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables
key = "HKEY_LOCAL_MACHINE"
registry = "SOFTWARE"
registry_no_recursion = os.path.join(registry, 'norecursion')
registry_recursion_1 = os.path.join(registry, 'recursion1')
registry_recursion_5 = os.path.join(registry, 'recursion5')
registry_recursion_29 = os.path.join(registry, 'recursion29')

test_regs = [os.path.join(key, registry_no_recursion),
             os.path.join(key, registry_recursion_1),
             os.path.join(key, registry_recursion_5),
             os.path.join(key, registry_recursion_29)]

rl_dict = {
    registry_no_recursion: '0',
    registry_recursion_1: '1',
    registry_recursion_5: '5',
    registry_recursion_29: '29'
}

conf_params = {'REGISTRY_0': os.path.join(key, registry_no_recursion),
               'LEVEL_0': rl_dict[registry_no_recursion],

               'REGISTRY_1': os.path.join(key, registry_recursion_1),
               'LEVEL_1': rl_dict[registry_recursion_1],

               'REGISTRY_2': os.path.join(key, registry_recursion_5),
               'LEVEL_2': rl_dict[registry_recursion_5],

               'REGISTRY_3': os.path.join(key, registry_recursion_29),
               'LEVEL_3': rl_dict[registry_recursion_29]
}

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

# Configurations

configurations_path = os.path.join(test_data_path, "wazuh_recursion_windows_registry.yaml")
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

p, m = generate_params(modes=['scheduled'], extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    return request.param


def extra_configuration_before_yield():
    for reg, rl in rl_dict.items():
        path = str(reg)
        for n in range(int(rl)):
            path = os.path.join(path, '' + str(n + 1))
        create_registry(registry_parser[key], path, KEY_WOW64_64KEY)

# Tests

@pytest.mark.parametrize('root_key, registry, arch, edge_limit, ignored_levels', [
    (key, registry_no_recursion, KEY_WOW64_64KEY, 2, 1),
    (key, registry_recursion_1, KEY_WOW64_64KEY, 2, 1),
    (key, registry_recursion_5, KEY_WOW64_64KEY, 2, 1),
    (key, registry_recursion_29, KEY_WOW64_64KEY, 2, 1)

])
def test_recursion_level(root_key, registry, arch, edge_limit, ignored_levels,
                         get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check that events are generated in the first and last `edge_limit` directory levels in the hierarchy
    It also checks that no events are generated for levels higher than the configured recursion level.

    Example:
        recursion_level = 10
        edge_limit = 2
        ignored_levels = 1
        key = "HKEY_LOCAL_MACHINE"
        registry = "SOFTWARE\\test_key"
        subkey = "subkey"

        With those parameters this function will create values and expect to detect 'added', 'modified' and 'deleted'
        events for the following registry only, as they are the first and last 2 subkeys within recursion
        level 10:

        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1
        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2
        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2\\3\\4\\5\\6\\7\\8\\9
        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2\\3\\4\\5\\6\\7\\8\\9\\10

        As ignored_levels value is 1, this function will also create files on the following subkeys and ensure that
        no events are raised as they are outside the recursion level specified:

        HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2\\3\\4\\5\\6\\7\\8\\9\\10\\11

    Parameters
    ----------
    root_key : str
        Registry key **STRING** (HKEY_* constants)
    registry : str
        The registry key being monitored by syscheck (indicated in the .conf file without the HKEY_* constant).
    arch : int
        Architecture of the registry key
    edge_limit : int
        Number of subkeys where the test will monitor events.
    ignored_levels : int
        Number of subkeys exceeding the specified recursion_level to verify events are not raised.
    """
    recursion_level = int(rl_dict[registry])
    path = registry

    # Check events in recursion level = 0
    registry_value_cud(root_key, path, wazuh_log_monitor, arch=arch, time_travel=True,
                       min_timeout=global_parameters.default_timeout)

    path_list = list()
    # For recursion lower levels, execute registry_value_cud in every level.
    if recursion_level < edge_limit:
        for level in range(recursion_level):
            path = os.path.join(path, str(level + 1))
            path_list.append(path)
    else:
        for level in range (recursion_level):
            path = os.path.join(path, str(level + 1))
            if level < edge_limit or level > recursion_level - edge_limit:
                path_list.append(path)

    # Create values only in the first/last `edge_limit` levels of recursion
    for registry_path in path_list:
        registry_value_cud(root_key, registry_path, wazuh_log_monitor, arch=arch, time_travel=True,
                           min_timeout=global_parameters.default_timeout, triggers_event=True)

    # Check that no alerts are generated when levels that exceed the specified recursion_level
    for n in range(recursion_level, recursion_level + ignored_levels):
        path = os.path.join(path, str(n + 1))
        registry_value_cud(root_key, path, wazuh_log_monitor, arch=arch, time_travel=True,
                           min_timeout=global_parameters.default_timeout, triggers_event=False)
