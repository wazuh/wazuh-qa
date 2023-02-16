'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM generates events
       while a database synchronization is being performed simultaneously on Linux systems.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: synchronization

targets:
    - agent
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
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    callback_detect_event, callback_real_time_whodata_started, callback_detect_synchronization
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_integrity_scan.yaml')
testdir1, testdir2 = test_directories

file_list = []
for i in range(3000):
    file_list.append(f'regular_{i}')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': [testdir1, testdir2]},
                                             modes=['realtime', 'whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def extra_configuration_before_yield():
    # Create 3000 files before restarting Wazuh to make sure the integrity scan will not finish before testing
    for testdir in test_directories:
        for file in file_list:
            create_file(REGULAR, testdir, file, content='Sample content')


def callback_integrity_or_whodata(line):
    if callback_detect_synchronization(line):
        return 1
    elif callback_real_time_whodata_started(line):
        return 2


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'synchronize_events_conf'}
])
def test_events_while_integrity_scan(tags_to_apply, get_configuration, configure_environment, install_audit,
                                     restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events while the synchronization is performed
                 simultaneously. For this purpose, the test will monitor a testing directory. Then, it
                 will check if the FIM 'integrity' and 'wodata' events are triggered. Finally, the test will
                 create a testing file and verify that the FIM 'added' event is generated.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - install_audit:
            type: fixture
            brief: install audit to check whodata.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that FIM 'integrity' and 'wodata' events are generated.
        - Verify that FIM 'added' event is generated when adding a testing file
          while the synchronization is performed.

    input_description: A test case (synchronize_events_conf) is contained in external YAML file
                       (wazuh_conf_integrity_scan.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the testing
                       directories to be monitored defined in this module.

    expected_output:
        - r'File integrity monitoring real-time Whodata engine started'
        - r'Initializing FIM Integrity Synchronization check'
        - r'.*Sending FIM event: (.+)$' ('added' event)

    tags:
        - realtime
        - who_data
    '''
    folder = testdir1 if get_configuration['metadata']['fim_mode'] == 'realtime' else testdir2

    # Wait for whodata to start and the synchronization check. Since they are different threads, we cannot expect
    # them to come in order every time
    if get_configuration['metadata']['fim_mode'] == 'whodata':
        value_1 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 2,
                                          callback=callback_integrity_or_whodata,
                                          error_message='Did not receive expected "File integrity monitoring '
                                                        'real-time Whodata engine started" or '
                                                        '"Executing FIM sync"').result()

        value_2 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 2,
                                          callback=callback_integrity_or_whodata,
                                          error_message='Did not receive expected "File integrity monitoring '
                                                        'real-time Whodata engine started" or '
                                                        '"Executing FIM sync"').result()
        assert value_1 != value_2, "callback_integrity_or_whodata detected the same message twice"

    else:
        # Check the integrity scan has begun
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout * 3,
                                callback=callback_detect_synchronization,
                                error_message='Did not receive expected '
                                              '"Initializing FIM Integrity Synchronization check" event')

    # Create a file and assert syscheckd detects it while doing the integrity scan
    file_name = 'file'
    create_file(REGULAR, folder, file_name, content='')
    sending_event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                            error_message='Did not receive expected '
                                                          '"Sending FIM event: ..." event').result()
    assert sending_event['data']['path'] == os.path.join(folder, file_name)
