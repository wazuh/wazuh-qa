'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM generates events
       for value operations in a monitored key hierarchy using multiple deep levels set in
       the 'recursion_level' attribute.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#windows-registry

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_recursion_level
'''
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

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('root_key, registry, arch, edge_limit, ignored_levels', [
    (key, registry_no_recursion, KEY_WOW64_64KEY, 2, 1),
    (key, registry_recursion_1, KEY_WOW64_64KEY, 2, 1),
    (key, registry_recursion_5, KEY_WOW64_64KEY, 2, 1),
    (key, registry_recursion_29, KEY_WOW64_64KEY, 2, 1)

])
def test_recursion_level(root_key, registry, arch, edge_limit, ignored_levels,
                         get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    # Example:
    #     recursion_level = 10
    #     edge_limit = 2
    #     ignored_levels = 1
    #     key = "HKEY_LOCAL_MACHINE"
    #     registry = "SOFTWARE\\test_key"
    #     subkey = "subkey"

    #     With those parameters this function will create values and expect to detect 'added', 'modified' and 'deleted'
    #     events for the following registry only, as they are the first and last 2 subkeys within recursion
    #     level 10:

    #     HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1
    #     HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2
    #     HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2\\3\\4\\5\\6\\7\\8\\9
    #     HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2\\3\\4\\5\\6\\7\\8\\9\\10

    #     As ignored_levels value is 1, this function will also create files on the following subkeys and ensure that
    #     no events are raised as they are outside the recursion level specified:

    #     HKEY_LOCAL_MACHINE\\SOFTWARE\\test_key\\1\\2\\3\\4\\5\\6\\7\\8\\9\\10\\11
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events in the first and last 'edge_limit' levels
                 in a key hierarchy. It also checks that no FIM events are generated for levels higher than
                 the configured in the 'recursion_level' attribute. For this purpose, the test will monitor
                 a testing key and create a hierarchy inside it. Once FIM starts, it will make value operations
                 in each level of that hierarchy. Finally, the test will verify that the FIM events are generated
                 in the edge level limits, and no FIM events are generated in the ignored levels.

    wazuh_min_version: 4.2.0

    parameters:
        - root_key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - registry:
            type: str
            brief: The registry key being monitored by syscheck.
        - arch:
            type: str
            brief: Architecture of the registry.
        - edge_limit:
            type: int
            brief: Number of subkeys where the test will monitor events.
        - ignored_levels:
            type: int
            brief: Number of subkeys exceeding the 'recursion_level' limit to verify events are not raised.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are generated for the value operations in a monitored key hierarchy up to
          the level set in the 'recursion_level' attribute.
        - Verify that no FIM events are generated in the ignored keys within a monitored key hierarchy.

    input_description: A test case (test_recursion_level_registry) is contained in external YAML file
                       (wazuh_recursion_windows_registry.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the testing registry
                       keys to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
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
        for level in range(recursion_level):
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
