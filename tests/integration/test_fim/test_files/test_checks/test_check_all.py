'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events generated contain only
       the 'check_' fields specified in the configuration when using the 'check_all' attribute along
       with other' check_' attributes.
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
from wazuh_testing.fim import (CHECK_ALL, CHECK_ATTRS, CHECK_GROUP, CHECK_INODE, CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SIZE, CHECK_SUM, LOG_FILE_PATH,
                               REQUIRED_ATTRIBUTES, regular_file_cud, generate_params, create_file, REGULAR,
                               check_time_travel, callback_detect_event, delete_file, modify_file)
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
    test_data_path, 'wazuh_check_all_windows.yaml' if sys.platform == 'win32' else 'wazuh_check_all.yaml')

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

parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM]),
                    (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM}),
                    (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA1SUM}),
                    (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM}),
                    (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SIZE}),
                    (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_OWNER}),
                    (testdir8, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM})]
if sys.platform == 'win32':
    parametrize_list.extend([
        (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_ATTRS}),
        (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MTIME})
    ])
else:
    parametrize_list.extend([
        (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_GROUP}),
        (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MTIME}),
        (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE})
    ])


@pytest.mark.parametrize('path, checkers', parametrize_list)
@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
def test_check_all_single(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                          wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generated events the checks specified in
                 the configuration. These checks are attributes indicating that a monitored file has been modified.
                 For example, if 'check_all=yes' and 'check_sum=no' are set for the same directory, 'syscheck' must
                 send an event containing every possible 'check_' except the checksums. For this purpose, the test
                 will monitor a testing folder using the 'check_all' attribute in conjunction with one 'check_'
                 on the same directory, having 'check_all' to 'yes' and the other one to 'no'.
                 Finally, the test will verify that the FIM events generated contain only the fields
                 of the 'checks' specified for the monitored folder.

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
                       (wazuh_check_all.yaml or wazuh_check_all_windows.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'test_check_all_single'}, get_configuration['tags'])
    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


if sys.platform == 'win32':
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM}),
                        (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
                        (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
                        (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - {CHECK_SIZE}),
                        (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_ATTRS} - {CHECK_PERM}),
                        (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM} - {CHECK_MTIME}),
                        (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL])
                        ]
else:
    parametrize_list = [(testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM}),
                        (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
                        (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
                        (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM} - {CHECK_SIZE}),
                        (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_OWNER} - {CHECK_GROUP}),
                        (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_PERM} - {CHECK_MTIME}),
                        (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE}),
                        (testdir0, REQUIRED_ATTRIBUTES[CHECK_ALL])
                        ]


@pytest.mark.parametrize('path, checkers', parametrize_list)
@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
def test_check_all(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                   wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generated events the checks specified in
                 the configuration. These checks are attributes indicating that a monitored file has been modified.
                 For example, if 'check_all=yes', 'check_sum=no', and 'check_md5sum=no' are set for the same directory,
                 'syscheck' must send an event containing every possible 'check_' except the 'md5' checksum.
                 For this purpose, the test will monitor a testing folder using the 'check_all' attribute in
                 conjunction with more than one 'check_' on the same directory, having 'check_all' to 'yes' and
                 the other ones to 'no'. Finally, the test will verify that the FIM events generated contain
                 only the fields of the 'checks' specified for the monitored folder.

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
                       (wazuh_check_all.yaml or wazuh_check_all_windows.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'test_check_all'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=15, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


@pytest.mark.parametrize('path, checkers', [(testdir1, {})])
def test_check_all_no(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                      wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generated events the checks specified in
                 the configuration. These checks are attributes indicating that a monitored file has been modified.
                 For example, when setting 'check_all' to 'no', only the 'type' and 'checksum' attributes should
                 appear in every FIM event. This will avoid any modification event. For this purpose, the test
                 will monitor a testing folder using the 'check_all=no' attribute, create a testing file inside it,
                 and verify that only the 'type' and 'checksum' attributes are in the 'added' event. Then, it
                 will modify the testing file and verify that no FIM events of type 'modified' are generated.
                 Finally, the test will delete the testing file and verify that only the 'type' and
                 'checksum' attributes are in the 'deleted' event.

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
        - Verify that FIM events generated are only of type 'added' and 'deleted' when
          the 'check_all=no' attribute is used.
        - Verify that FIM events generated only contain the 'type' and 'checksum' attributes
          when the 'check_all=no' attribute is used.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_check_all.yaml or wazuh_check_all_windows.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', and 'deleted' event)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'test_check_all_no'}, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create regular file and dont expect any check
    file = 'regular'
    create_file(REGULAR, path, file)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    create_event = wazuh_log_monitor.start(callback=callback_detect_event, timeout=15,
                                           error_message='Did not receive expected '
                                                         '"Sending FIM event: ..." event').result()
    assert create_event['data']['type'] == 'added'
    assert list(create_event['data']['attributes'].keys()) == ['type', 'checksum']

    # Delete regular file and dont expect any check. Since it is not using any check, modification events will not
    # be triggered
    modify_file(path, file, 'Sample modification')
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(callback=callback_detect_event, timeout=5)
        raise AttributeError(f'Unexpected event {event}')

    delete_file(path, file)
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    delete_event = wazuh_log_monitor.start(callback=callback_detect_event, timeout=15,
                                           error_message='Did not receive expected '
                                                         '"Sending FIM event: ..." event').result()
    assert delete_event['data']['type'] == 'deleted', f'Current value is {delete_event["data"]["type"]}'
    assert list(delete_event['data']['attributes'].keys()) == ['type', 'checksum'], \
        f'Current value is {list(delete_event["data"]["attributes"].keys())}'
