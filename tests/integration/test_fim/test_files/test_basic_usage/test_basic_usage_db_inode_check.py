'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check for false positives due
       to possible inconsistencies with 'inodes' in the FIM database.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 0

modules:
    - fim

components:
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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
    - https://en.wikipedia.org/wiki/Inode

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
import shutil

import pytest
import wazuh_testing.fim as fim
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Variables

monitored_folder = os.path.join(PREFIX, 'testdir')
test_directories = [monitored_folder]

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_check_inodes.yaml')
file_list = [f"file{i}" for i in range(10)]

# configurations

monitoring_modes = ['scheduled']

conf_params = {'TEST_DIRECTORIES': test_directories, 'MODULE_NAME': __name__}
params, metadata = fim.generate_params(extra_params=conf_params, modes=monitoring_modes,
                                       apply_to_all=({'CHECK_TYPE': check} for check in ['yes', 'no']))

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def restart_syscheck_function(get_configuration, request):
    """
    Reset ossec.log and start a new monitor.
    """
    control_service('stop', daemon='wazuh-syscheckd')
    truncate_file(fim.LOG_FILE_PATH)
    file_monitor = FileMonitor(fim.LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon='wazuh-syscheckd')


@pytest.fixture(scope='function')
def wait_for_fim_start_function(get_configuration, request):
    """
    Wait for realtime start, whodata start or end of initial FIM scan.
    """
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    fim.detect_initial_scan(file_monitor)


# tests
@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('test_cases', [0, 1, 2])
def test_db_inode_check(test_cases, get_configuration, configure_environment, restart_syscheck_function,
                        wait_for_fim_start_function):
    '''
    description: Check for false positives due to possible inconsistencies with inodes in the FIM database.
                 For example, with 'check_mtime=no' and 'check_inode=no', no modification events should appear,
                 and using 'check_mtime=yes' and 'check_inode=yes', since the 'mtime' and 'inode' attributes
                 are modified, modification events should appear.
                 For this purpose, the test will monitor a folder using the 'scheduled' monitoring mode,
                 create ten files with some content and wait for the scan. Then, remove the files and
                 create them again (adding one more at the beginning or deleting it) with different inodes.
                 Finally, the test changes the system time until the next scheduled scan and check
                 if there are any unexpected events in the log.

    wazuh_min_version: 4.2.0

    parameters:
        - test_cases:
            type: int
            brief: Test case number.
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
        - Verify that the FIM database does not become inconsistent due to the change of inodes,
          whether or not 'check_mtime' and 'check_inode' are enabled.

    input_description: Two test cases defined in this module, and the configuration settings for
                       the 'wazuh-syscheckd' daemon (tag ossec_conf) which are contained in external
                       YAML file (wazuh_conf_check_inodes.yaml).

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    aux_file_list = file_list.copy()

    for file in aux_file_list:
        fim.create_file(fim.REGULAR, monitored_folder, file, content=file)

    # Time travel after creating the required files
    fim.check_time_travel(True, monitor=wazuh_log_monitor)

    shutil.rmtree(monitored_folder, ignore_errors=True)

    if test_cases == 0:
        # First case, adding a file ahead
        aux_file_list.insert(0, "file")
    elif test_cases == 1:
        # Second case, removing the first file
        aux_file_list.pop(0)
    elif test_cases == 2:
        # Third case, rotating files
        aux_file_list.pop(-1)
        aux_file_list.insert(0, "file9")

    for file in aux_file_list:
        fim.create_file(fim.REGULAR, monitored_folder, file, content=file)

    # Time travel after delete and create again a different number of files
    fim.check_time_travel(True, monitor=wazuh_log_monitor)

    if get_configuration['metadata']['check_type'] == 'yes':
        callback_test = fim.callback_detect_modified_event_with_inode_mtime
    else:
        callback_test = fim.callback_detect_modified_event

    shutil.rmtree(monitored_folder, ignore_errors=True)

    # Check unexpected events
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_test).result()
        if test_cases == 2:
            pytest.xfail('Xfailing due to false positive in special case, issue related: \
                          https://github.com/wazuh/wazuh/issues/7829')
        raise AttributeError(f'Unexpected event {event}')
