'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. All these tests will be performed using ambiguous directory configurations,
       such as directories and subdirectories with opposite monitoring settings. In particular, it
       will check that duplicate events are not generated when multiple configurations are used
       to monitor the same directory.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
    - agent

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
    - fim_ambiguous_confs
'''
import codecs
import os
from pathlib import Path

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.tools.logging import logging_message
from wazuh_testing.fim import LOG_FILE_PATH, modify_file_group, modify_file_content, modify_file_owner, \
    modify_file_permission, check_time_travel, callback_detect_event, get_fim_mode_param, deepcopy, create_file, \
    REGULAR, generate_params, validate_event, CHECK_PERM, CHECK_SIZE, WAZUH_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=2), pytest.mark.linux, pytest.mark.win32]

# variables
test_directories = [os.path.join(PREFIX, 'testdir1')] * 2
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_dup_entries.yaml')
testdir1, _ = test_directories

# Configuration

p, m = generate_params(extra_params={'MODULE_NAME': __name__, 'TEST_DIRECTORIES': directory_str})

params, metadata = list(), list()
for mode in ['scheduled', 'realtime', 'whodata']:
    p_fim, m_fim = get_fim_mode_param(mode, key='FIM_MODE')
    if p_fim:
        for p_dict, m_dict in zip(p, m):
            p_dict.update(p_fim.items())
            m_dict.update(m_fim.items())
            params.append(deepcopy(p_dict))
            metadata.append(deepcopy(m_dict))

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions
def check_event(previous_mode: str, previous_event: dict, file: str):
    """Check if a file modification does not trigger an event but its creation did.

    In case of timeout, checks that the type of the previous event was addition
    on the correct path and with correct mode.

    Parameters
    ----------
    previous_mode : str
        String that contains the mode that the previous event should have
    previous_event : dict
        Dict with the previous event
    file : str
        String that contains the name of the monitored file

    Returns
    -------
    dict
        Dict with the triggered event

    """
    current_event = None
    try:
        logging_message('test', 'VV',  'Checking for a second event...')
        current_event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                callback=callback_detect_event,
                                                error_message='Did not receive expected '
                                                              '"Sending FIM event: ..." event').result()
    except TimeoutError:
        if not isinstance(previous_event["data"]["path"], list):
            previous_event["data"]["path"] = [previous_event["data"]["path"]]
        if 'added' not in previous_event['data']['type'] and \
                os.path.join(testdir1, file) in list(previous_event['data']['path']) and \
                previous_mode in previous_event['data']['mode']:
            raise AttributeError(f'It was expected that the previous event would be an "added" event, '
                                 f'its type is "{previous_event["data"]["type"]}", '
                                 f'also the "{os.path.join(testdir1, file)}" file would be in '
                                 f'{previous_event["data"]["path"]} and that the "{previous_mode}" mode would be '
                                 f'"{previous_event["data"]["mode"]}"')

    return current_event


# tests

@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_duplicate_entries(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if when using multiple configurations on the same directory that can generate the same event,
                 only one is finally generated. For example, when monitoring the same directory using the 'whodata'
                 and 'realtime' attributes and modifying a file, two FIM events should not be generated.
                 For this purpose, it applies the test case configuration, adds a test file in the directory,
                 and finally checks that only one FIM event has been generated.

    wazuh_min_version: 4.2.0

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
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that only one FIM event is generated when the testing file is created.

    input_description: One test cases (ossec_conf_duplicate_simple) is contained in external YAML file
                       (wazuh_conf_dup_entries.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon and testing directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - scheduled
        - realtime
        - time_travel
    '''
    logging_message('test', 'VV',  'Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_simple'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']

    scheduled = mode == 'scheduled'
    mode = "realtime" if mode == "real-time" else mode

    logging_message('test', 'VV',  f'Adding file {os.path.join(testdir1, file)}, content: " "')
    create_file(REGULAR, testdir1, file, content=' ')

    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled)
    logging_message('test', 'VV',  'Checking the event...')
    event1 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     error_message=f'Did not receive expected event for file '
                                                   f'{os.path.join(testdir1, file)}'
                                     ).result()

    # Check for a second event
    event2 = check_event(previous_mode=mode, previous_event=event1, file=file)
    assert event2 is None, "Multiple events created"

@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_duplicate_entries_sregex(get_configuration, configure_environment,
                                  restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if when using multiple 'sregex' patterns of the 'restrict' attribute in the same directory,
                 and that these can match the same file, only one FIM event is generated. For example, when
                 monitoring the same directory using 'restrict="^good.*$"' and 'restrict="^he.*$"', only
                 the filenames that match with this regex '^he.*$' should generate FIM events.
                 For this purpose, it applies the test case configuration, adds and modifies a test file in
                 the directory, checks that only one FIM event has been generated for each operation, and finally
                 verifies that only one FIM event has been generated for each operation.

    wazuh_min_version: 4.2.0

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
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that only one FIM event is generated when the testing file is created.
        - Verify that only one FIM event is generated when the testing file is modified.

    input_description: One test case (ossec_conf_duplicate_sregex) is contained in external YAML file
                       (wazuh_conf_dup_entries.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon and testing directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - scheduled
        - time_travel
    '''
    logging_message('test', 'VV',  'Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_sregex'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']
    scheduled = mode == 'scheduled'

    # Check for an event
    logging_message('test', 'VV',  f'Adding file {os.path.join(testdir1, file)}, content: " "')
    create_file(REGULAR, testdir1, file, content=' ')
    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        logging_message('test', 'VV',  'Checking the event...')
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event).result()
        raise AttributeError(f'Unexpected event {event}')

    # Check for a second event
    logging_message('test', 'VV',  f'Modifying {os.path.join(testdir1, file)} content')
    modify_file_content(testdir1, file)
    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        logging_message('test', 'VV',  'Checking the event...')
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event).result()
        raise AttributeError(f'Unexpected event {event}')

@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_duplicate_entries_report(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if when using multiple configurations using the 'report_changes' attribute
                 in the same directory, only the last configuration is taken into account. For example,
                 when monitoring the same directory using 'report_changes="yes"' and 'report_changes="no"',
                 no 'diff' files should be generated when modifying a file since 'report_changes="no"' is
                 the last detected configuration.
                 For this purpose, it applies the test case configuration, adds and modifies a test file
                 in the directory, checks that FIM event has been generated for each operation,
                 and finally verifies that a 'diff' file has not been created.

    wazuh_min_version: 4.2.0

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
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are generated when the testing file is created and modified.
        - Verify that a 'diff' file has not been created when modifying the test file.

    input_description: One test case (ossec_conf_duplicate_report) is contained in external YAML file
                       (wazuh_conf_dup_entries.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon and testing directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - scheduled
        - time_travel
    '''
    logging_message('test', 'VV',  'Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_report'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']
    scheduled = mode == 'scheduled'

    # Check for an event
    logging_message('test', 'VV',  f'Adding file {os.path.join(testdir1, file)}, content: " "')
    create_file(REGULAR, testdir1, file, content=' ')
    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message=f'Did not receive expected event for file '
                                          f'{os.path.join(testdir1, file)}').result()

    # Check for a second event
    logging_message('test', 'VV',  f'Modifying {os.path.join(testdir1, file)} content')
    modify_file_content(testdir1, file)
    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message=f'Did not receive expected event for file '
                                          f'{os.path.join(testdir1, file)}').result()

    assert not os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'diff', 'local', testdir1[1:], file)), \
        'Error: Diff file created'

@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_duplicate_entries_complex(get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_fim_start):
    '''
    description: Check if when using multiple configurations using diferent 'check_' attributes in
                 the same directory, only the last configuration is taken into account. For example,
                 when monitoring the same directory using 'check_owner="yes" check_inode="yes"' and
                 'check_size="yes" check_perm="yes"', only 'size' and 'permissions' fields files
                 should be generated in the FIM events since 'check_size="yes" check_perm="yes"'
                 is the last detected configuration.
                 For this purpose, it applies the test case configuration, adds and modifies
                 a testing file in the directory, checks that one FIM event is generated when
                 modifying the size or permissions of the test file, and finally verify that
                 the 'size' and 'permissions' fields have been generated in that event.

    wazuh_min_version: 4.2.0

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
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM event is generated when the testing file is added.
        - Verify that modifications not related to the size or permissions
          of the testing file do not generate FIM events.
        - Verify that FIM events are generated that include the 'size' and 'permissions' fields
          when these are modified in the test file.

    input_description: One test case (ossec_conf_duplicate_complex) is contained in external YAML file
                       (wazuh_conf_dup_entries.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon and testing directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - scheduled
        - time_travel
    '''
    def replace_character(old, new, path):
        f = codecs.open(path, encoding='utf-8')
        content = f.read()
        content.replace(old, new)
        f.close()

    logging_message('test', 'VV',  'Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_complex'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']

    scheduled = mode == 'scheduled'
    mode = "realtime" if mode == "real-time" else mode

    logging_message('test', 'VV',  f'Adding file {os.path.join(testdir1, file)}, content: "testing"')
    create_file(REGULAR, testdir1, file, content='testing')
    file_path = os.path.join(testdir1, file)

    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    logging_message('test', 'VV',  'Checking the event...')
    event1 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     error_message=f'It was expected that a "Sending FIM event:" '
                                                   f'event would be generated for file {os.path.join(testdir1, file)}'
                                     ).result()

    # Replace character, change the group and ownership and touch the file
    logging_message('test', 'VV',  f'Replacing a character of {os.path.join(testdir1, file)} content')
    replace_character('i', '1', file_path)
    logging_message('test', 'VV',  f'Modifying {os.path.join(testdir1, file)}\'s group')
    modify_file_group(testdir1, file)
    logging_message('test', 'VV',  f'Modifying {os.path.join(testdir1, file)}\'s owner')
    modify_file_owner(testdir1, file)
    logging_message('test', 'VV',  f'Adding new file {file_path}')
    Path(file_path).touch()

    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    event2 = check_event(previous_mode=mode, previous_event=event1, file=file)
    assert event2 is None, "Multiple events created"

    # Change the permissions and the size of the file
    logging_message('test', 'VV',  f'Modifying {os.path.join(testdir1, file)}\'s permissions')
    modify_file_permission(testdir1, file)
    logging_message('test', 'VV',  f'Modifying {os.path.join(testdir1, file)} content')
    modify_file_content(testdir1, file)

    logging_message('test', 'VV',  f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    logging_message('test', 'VV',  'Checking the event...')
    event3 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     error_message=f'Did not receive expected "Sending FIM event:" '
                                                   f'event for file {os.path.join(testdir1, file)}').result()
    validate_event(event3, [CHECK_PERM, CHECK_SIZE], mode=mode)
