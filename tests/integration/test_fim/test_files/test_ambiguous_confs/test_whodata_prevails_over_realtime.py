'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'who-data' feature of the File Integrity Monitoring (FIM) system
       works properly. 'who-data' information contains the user who made the changes on the monitored
       files and also the program name or process used to carry them out. In particular, it will be
       verified that the value of the 'whodata' attribute prevails over the 'realtime' one.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_ambiguous_complex

targets:
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/auditing-whodata/who-linux.html
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
    - fim_ambiguous_confs
'''
import os

import pytest
from wazuh_testing import global_parameters, LOG_FILE_PATH, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.file import create_file, delete_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.event_monitor import callback_detect_event
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

# Configuration paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_templates')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_whodata_prevails_over_realtime.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_whodata_prevails_over_realtime.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
for count, value in enumerate(configuration_parameters):
    configuration_parameters[count]['TEST_DIR'] = test_directories[0]
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


# Test
@pytest.mark.parametrize('test_folders', [test_directories], scope="module", ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_whodata_prevails_over_realtime(configuration, metadata, set_wazuh_configuration, test_folders,
                                        create_monitored_folders_module, configure_local_internal_options_function,
                                        restart_syscheck_function, wait_syscheck_start):
    '''
    description: Check if when using the options who-data and real-time at the same time
                 the value of 'whodata' is the one used. For example, when using 'whodata=yes'
                 and 'realtime=no' on the same directory, real-time file monitoring
                 will be enabled, as who-data requires it.
                 For this purpose, the configuration is applied and it is verified that when
                 'who-data' is set to 'yes', the 'realtime' value is not taken into account,
                 enabling in this case the real-time file monitoring.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder for monitoring
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Create file and detect event creation event
            - Validate mode is whodata
            - Delete file and detect event deletion event
            - Validate mode is whodata
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders_module:
            type: fixture
            brief: Create a given list of folders when the module starts. Delete the folders at the end of the module.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options.conf file.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.
        - wait_syscheck_start:
            type: fixture
            brief: check that the starting FIM scan is detected.

    assertions:
        - Verify that real-time whodata thread active.

    input_description: The file 'configuration_whodata_prevails_over_realtime.yaml' provides the configuration
                       template.
                       The file 'cases_whodata_prevails_over_realtime.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - who_data
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    filename = "testfile"

    create_file(REGULAR, test_directories[0], filename, content="")
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event).result()

    assert event['data']['mode'] == 'whodata', f"Unexpected event mode found:{event['data']['mode']}, expected whodata"
    assert event['data']['type'] == 'added', f"Unexpected event type found:{event['data']['type']}, expected added"
    assert os.path.join(test_directories[0], filename) in event['data']['path'], 'Unexpected file path found'

    delete_file(os.path.join(test_directories[0], filename))
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event).result()

    assert event['data']['mode'] == 'whodata', f"Unexpected event mode found:{event['data']['mode']}, expected whodata"
    assert event['data']['type'] == 'deleted', f"Unexpected event type found:{event['data']['type']}, expected deleted"
    assert os.path.join(test_directories[0], filename) in event['data']['path'], 'Unexpected file path found'
