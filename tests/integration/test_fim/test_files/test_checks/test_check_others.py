'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events generated contain only
       the 'check_' fields specified in the configuration when using the 'check_' attributes individually
       without using the 'check_all=yes' attribute.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

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
    - fim_checks
'''
import os
import sys

import pytest
from wazuh_testing.fim import (CHECK_ATTRS, CHECK_GROUP, CHECK_INODE, CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SIZE, CHECK_SUM,
                               LOG_FILE_PATH, REQUIRED_ATTRIBUTES, regular_file_cud, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3'), os.path.join(PREFIX, 'testdir4'),
                    os.path.join(PREFIX, 'testdir5'), os.path.join(PREFIX, 'testdir6'),
                    os.path.join(PREFIX, 'testdir7'), os.path.join(PREFIX, 'testdir8'),
                    os.path.join(PREFIX, 'testdir9'), os.path.join(PREFIX, 'testdir0')]
configurations_path = os.path.join(
    test_data_path, 'wazuh_check_others_windows.yaml' if sys.platform == 'win32' else 'wazuh_check_others.yaml')

testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories

# configurations

p, m = generate_params()
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM]),
                    (testdir2, {CHECK_MD5SUM}),
                    (testdir3, {CHECK_SHA1SUM}),
                    (testdir4, {CHECK_SHA256SUM}),
                    (testdir5, {CHECK_SIZE}),
                    (testdir6, {CHECK_OWNER}),
                    (testdir8, {CHECK_PERM})]
if sys.platform == 'win32':
    parametrize_list.extend([
        (testdir7, {CHECK_ATTRS}),
        (testdir9, {CHECK_MTIME})
    ])
else:
    parametrize_list.extend([
        (testdir7, {CHECK_GROUP}),
        (testdir9, {CHECK_MTIME}),
        (testdir0, {CHECK_INODE})
    ])

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_others_individually(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generate events the checks specified in
                 the configuration. These checks are attributes indicating that a monitored file has been modified.
                 For example, if 'check_all=no' and 'check_sum=yes' are set for the same directory, 'syscheck' must
                 send an event containing only the checksums. For this purpose, the test will monitor a testing folder
                 using the 'check_all=no' attribute (in order to avoid using the default 'check_all' configuration)
                 in conjunction with one 'check_' on the same directory. Finally, the test will verify that
                 the FIM events generated contain only the fields of the 'checks' specified for the monitored folder.

    wazuh_min_version: 4.2.0

    parameters:
        - path:
            type: str
            brief: Directory where the file is being created and monitored.
        - checkers:
            type: set
            brief: Checks to be compared to the actual event check list.
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
        - Verify that the FIM events generated contain only the 'check_' fields specified in the configuration.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_check_others.yaml or wazuh_check_others_windows.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'test_check_others_individually'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM] | {CHECK_SIZE}),
                    (testdir3, {CHECK_SHA1SUM} | {CHECK_SHA256SUM}),
                    (testdir6, {CHECK_PERM} | {CHECK_MTIME}),
                    (testdir8, {CHECK_SHA256SUM})]

if sys.platform == 'win32':
    parametrize_list.extend([
        (testdir2, {CHECK_MD5SUM} | {CHECK_OWNER} | {CHECK_MTIME}),
        (testdir4, {CHECK_SIZE} | {CHECK_PERM} | {CHECK_ATTRS}),
        (testdir5, {CHECK_OWNER} | {CHECK_ATTRS}),
        (testdir7, {CHECK_ATTRS} | {CHECK_MTIME})
    ])
else:
    parametrize_list.extend([
        (testdir2, {CHECK_MD5SUM} | {CHECK_GROUP} | {CHECK_MTIME}),
        (testdir4, {CHECK_SIZE} | {CHECK_PERM} | {CHECK_INODE}),
        (testdir5, {CHECK_OWNER} | {CHECK_GROUP}),
        (testdir7, {CHECK_GROUP} | {CHECK_MTIME})
    ])


@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('path, checkers', parametrize_list)
def test_check_others(path, checkers, get_configuration, configure_environment,
                      restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generate events the checks specified in
                 the configuration. These checks are attributes indicating that a monitored file has been modified.
                 For example, if 'check_md5sum=yes', 'check_all=no' and 'check_mtime=yes' are set for
                 the same directory, 'syscheck' must send an event containing only the file modification time.
                 For this purpose, the test will monitor a testing folder using the 'check_all=no' attribute
                 (in order to avoid using the default 'check_all' configuration) in conjunction with more than
                 one 'check_' on the same directory. Finally, the test will verify that the FIM events generated
                 contain only the fields of the 'checks' specified for the monitored folder.
                 In adittion, the order of the 'checks' (including 'check_all=no') will be different on each
                 test case to check the behavior of the 'check_all=no' attribute.

    wazuh_min_version: 4.2.0

    parameters:
        - path:
            type: str
            brief: Directory where the file is being created and monitored.
        - checkers:
            type: set
            brief: Checks to be compared to the actual event check list.
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
        - Verify that the FIM events generated contain only the 'check_' fields specified in the configuration.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_check_others.yaml or wazuh_check_others_windows.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'test_check_others'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
