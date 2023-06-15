'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. In particular, these tests will check if FIM changes
       the monitoring mode from 'realtime' to 'scheduled' when it is not supported.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_basic_usage

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - macos
    - solaris

os_version:
    - macOS Catalina
    - macOS Server
    - Solaris 10
    - Solaris 11

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_basic_usage
'''
import os

import pytest
from wazuh_testing import LOG_FILE_PATH
from wazuh_testing.fim import detect_initial_scan, callback_ignore_realtime_flag
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.utils import generate_params, regular_file_cud


# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# variables

realtime_flag_timeout = 60
directory_str = os.path.join(PREFIX, 'dir')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_check_realtime.yaml')
test_file = 'testfile.txt'
test_directories = [directory_str]


# Configurations
conf_params = {'TEST_DIRECTORIES': directory_str}
parameters, metadata = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
local_internal_options = {'syscheck.debug': '2', 'monitord.rotate_log': '0'}
daemons_handler_configuration = {'daemons': ['wazuh-syscheckd']}


# Fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_realtime_unsupported(get_configuration, configure_environment, file_monitoring,
                              configure_local_internal_options_module, daemons_handler_module):
    '''
    description: Check if the current OS platform falls to the 'scheduled' mode when 'realtime' is not available.
                 For this purpose, the test performs a CUD set of operations to a file with 'realtime' mode set as
                 the monitoring option in the 'ossec.conf' file. Firstly it checks for the initial 'realtime' event
                 appearing in the logs, and if the current OS does not support it, wait for the initial FIM scan
                 mode. After this, the set of operations takes place and the expected behavior is the events will be
                 generated with 'scheduled' mode and not 'realtime' as it is set in the configuration.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler_module:
            type: fixture
            brief: Handle the Wazuh daemons.

    assertions:
        - Verify that FIM changes the monitoring mode from 'realtime' to 'scheduled' when it is not supported.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf_check_realtime.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is combined
                       with the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - realtime
        - scheduled
    '''
    log_monitor.start(timeout=realtime_flag_timeout, callback=callback_ignore_realtime_flag,
                      error_message="Did not receive expected 'Ignoring flag for real time monitoring on  \
                                     directory: ...' event", update_position=False)

    detect_initial_scan(log_monitor)

    regular_file_cud(directory_str, log_monitor, file_list=[test_file], triggers_event=True,
                     event_mode="scheduled", min_timeout=15)
