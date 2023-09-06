'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM disables the synchronization
       of file/registry on Windows systems when the 'enabled' tag of the synchronization option is
       set to 'no'.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: synchronization

targets:
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_synchronization
'''
import os

import pytest
from wazuh_testing import global_parameters, LOG_FILE_PATH, REGULAR, DATA
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import create_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules.fim import (TEST_DIR_1, WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, TEST_DIRECTORIES,
                                       YAML_CONF_SYNC_WIN32, TEST_REGISTRIES, SYNCHRONIZATION_ENABLED,
                                       SYNCHRONIZATION_REGISTRY_ENABLED)
from wazuh_testing.modules.fim.event_monitor import CB_INTEGRITY_CONTROL_MESSAGE
from wazuh_testing.modules.fim.utils import generate_params

# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), DATA)


configurations_path = os.path.join(test_data_path, YAML_CONF_SYNC_WIN32)

test_directories = [os.path.join(PREFIX, TEST_DIR_1)]
test_regs = [os.path.join(WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY)]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

conf_params = {TEST_DIRECTORIES: test_directories[0],
               TEST_REGISTRIES: test_regs[0],
               SYNCHRONIZATION_ENABLED: 'no',
               SYNCHRONIZATION_REGISTRY_ENABLED: 'no'}

# configurations

parameters, metadata = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def create_a_file(get_configuration):
    """Create a file previous to restart syscheckd"""
    create_file(REGULAR, test_directories[0], 'test_file.txt')


# Tests
def test_sync_disabled(get_configuration, configure_environment, create_a_file, restart_syscheckd,
                       wait_for_fim_start_sync):
    '''
    description: Check if the 'wazuh-syscheckd' daemon uses the value of the 'enabled' tag to start/stop
                 the file/registry synchronization. For this purpose, the test will monitor a directory/key.
                 Finally, it will verify that no FIM 'integrity' event is generated when the synchronization
                 is disablede.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start_sync:
            type: fixture
            brief: Wait for end of initial FIM scan.
    assertions:
        - Verify that no FIM 'integrity' events are generated when the value
          of the 'enabled' tag is set to 'no' (synchronization disabled).
    input_description: Different test cases are contained in external YAML file (wazuh_sync_conf_win32.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined with
                       the testing directory/key to be monitored defined in this module.
    expected_output:
        - r'.*Sending integrity control message'
    tags:
        - scheduled
        - time_travel
        - realtime
        - who_data
    '''
    # The file synchronization event shouldn't be triggered
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=generate_monitoring_callback(CB_INTEGRITY_CONTROL_MESSAGE),
                                        update_position=True).result()
