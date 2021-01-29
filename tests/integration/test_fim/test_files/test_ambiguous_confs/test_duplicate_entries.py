# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import codecs
import os
from pathlib import Path

import pytest
from wazuh_testing import global_parameters
from wazuh_testing import logger
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
        logger.info('Checking for a second event...')
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


def test_duplicate_entries(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """Check if syscheckd ignores duplicate entries.
       For instance:
           - The second entry should prevail over the first one.
            <directories realtime="yes">/home/user</directories> (IGNORED)
            <directories whodata="yes">/home/user</directories>
        OR
           - Just generate one event.
            <directories realtime="yes">/home/user,/home/user</directories>
    """
    logger.info('Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_simple'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']

    scheduled = mode == 'scheduled'
    mode = "realtime" if mode == "real-time" else mode

    logger.info(f'Adding file {os.path.join(testdir1, file)}, content: " "')
    create_file(REGULAR, testdir1, file, content=' ')

    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled)
    logger.info('Checking the event...')
    event1 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     error_message=f'Did not receive expected event for file '
                                                   f'{os.path.join(testdir1, file)}'
                                     ).result()

    # Check for a second event
    event2 = check_event(previous_mode=mode, previous_event=event1, file=file)
    assert event2 is None, "Multiple events created"


def test_duplicate_entries_sregex(get_configuration, configure_environment,
                                  restart_syscheckd, wait_for_fim_start):
    """Check if syscheckd ignores duplicate entries, sregex patterns of restrict.
       For instance:
           - The second entry should prevail over the first one.
            <directories restrict="^good.*$">/home/user</directories> (IGNORED)
            <directories restrict="^he.*$">/home/user</directories>
       In this case, only the filenames that match with this regex '^he.*$'
    """
    logger.info('Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_sregex'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']
    scheduled = mode == 'scheduled'

    # Check for an event
    logger.info(f'Adding file {os.path.join(testdir1, file)}, content: " "')
    create_file(REGULAR, testdir1, file, content=' ')
    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        logger.info('Checking the event...')
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event).result()
        raise AttributeError(f'Unexpected event {event}')

    # Check for a second event
    logger.info(f'Modifying {os.path.join(testdir1, file)} content')
    modify_file_content(testdir1, file)
    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        logger.info('Checking the event...')
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_event).result()
        raise AttributeError(f'Unexpected event {event}')


def test_duplicate_entries_report(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """Check if syscheckd ignores duplicate entries, report changes.
       For instance:
           - The second entry should prevail over the first one.
            <directories report_changes="yes">/home/user</directories> (IGNORED)
            <directories report_changes="no">/home/user</directories>
    """
    logger.info('Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_report'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']
    scheduled = mode == 'scheduled'

    # Check for an event
    logger.info(f'Adding file {os.path.join(testdir1, file)}, content: " "')
    create_file(REGULAR, testdir1, file, content=' ')
    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message=f'Did not receive expected event for file '
                                          f'{os.path.join(testdir1, file)}').result()

    # Check for a second event
    logger.info(f'Modifying {os.path.join(testdir1, file)} content')
    modify_file_content(testdir1, file)
    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message=f'Did not receive expected event for file '
                                          f'{os.path.join(testdir1, file)}').result()

    assert not os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'diff', 'local', testdir1[1:], file)), \
        'Error: Diff file created'


def test_duplicate_entries_complex(get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_fim_start):
    """Check if syscheckd ignores duplicate entries, complex entries.
       For instance:
           - The second entry should prevail over the first one.
            <directories check_all="no" check_owner="yes" check_inode="yes">/home/user</directories> (IGNORED)
            <directories check_all="no" check_size="yes" check_perm="yes">/home/user</directories>
       In this case, it only check if the permissions or the size of the file changes
    """

    def replace_character(old, new, path):
        f = codecs.open(path, encoding='utf-8')
        content = f.read()
        content.replace(old, new)
        f.close()

    logger.info('Applying the test configuration')
    check_apply_test({'ossec_conf_duplicate_complex'}, get_configuration['tags'])
    file = 'hello'
    mode = get_configuration['metadata']['fim_mode']

    scheduled = mode == 'scheduled'
    mode = "realtime" if mode == "real-time" else mode

    logger.info(f'Adding file {os.path.join(testdir1, file)}, content: "testing"')
    create_file(REGULAR, testdir1, file, content='testing')
    file_path = os.path.join(testdir1, file)

    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    logger.info('Checking the event...')
    event1 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     error_message=f'It was expected that a "Sending FIM event:" '
                                                   f'event would be generated for file {os.path.join(testdir1, file)}'
                                     ).result()

    # Replace character, change the group and ownership and touch the file
    logger.info(f'Replacing a character of {os.path.join(testdir1, file)} content')
    replace_character('i', '1', file_path)
    logger.info(f'Modifying {os.path.join(testdir1, file)}\'s group')
    modify_file_group(testdir1, file)
    logger.info(f'Modifying {os.path.join(testdir1, file)}\'s owner')
    modify_file_owner(testdir1, file)
    logger.info(f'Adding new file {file_path}')
    Path(file_path).touch()

    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    event2 = check_event(previous_mode=mode, previous_event=event1, file=file)
    assert event2 is None, "Multiple events created"

    # Change the permissions and the size of the file
    logger.info(f'Modifying {os.path.join(testdir1, file)}\'s permissions')
    modify_file_permission(testdir1, file)
    logger.info(f'Modifying {os.path.join(testdir1, file)} content')
    modify_file_content(testdir1, file)

    logger.info(f'Time travel: {scheduled}')
    check_time_travel(scheduled, monitor=wazuh_log_monitor)
    logger.info('Checking the event...')
    event3 = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                     callback=callback_detect_event,
                                     error_message=f'Did not receive expected "Sending FIM event:" '
                                                   f'event for file {os.path.join(testdir1, file)}').result()
    validate_event(event3, [CHECK_PERM, CHECK_SIZE], mode=mode)
