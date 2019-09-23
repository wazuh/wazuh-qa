# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import pytest
import re
import stat

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor


test_data_path = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'data')


def create_folder_hierarchy(basename, num_subdirectories):
    """Create a hierarchy of folders on `basename` with as many subdirectories recursively as specified.
        Example:
            create_folder_hierarchy("/testdir1", 3)
        
        Result:
            /testdir1/subdir1/subdir2/subdir3/

        :param basename string The root path of the hierarchy.
        :param num_subdirectories int The number of subdirectories to create recursively
    """
    path = basename
    for n in range(1, num_subdirectories + 1):
        path = os.path.join(path, "subdir" + str(n))
    return path


test_directories = [create_folder_hierarchy("/testdir1", 0),
                    create_folder_hierarchy("/testdir1", 1),
                    create_folder_hierarchy("/testdir2", 0),
                    create_folder_hierarchy("/testdir2", 1),
                    create_folder_hierarchy("/testdir1", 5),
                    create_folder_hierarchy("/testdir1", 318)
                    ]
testdir1, testdir1_sub1, testdir2, testdir2_sub1, testdir1_sub5, testdir1_sub320 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


def assert_event(expected_type, path, should_be_triggered):
    """Check if an event has been rised with the specified type and path.
        Used to check if the syscheck has noticed the creation, modification or deletion of a file.

        :param expected_type string The type of Event to check (added, modified or deleted)
        :param path string The full path to the file that generated the event
        :param should_be_triggered bool True if an event must be generated, False otherwise
    """
    try:
        event = wazuh_log_monitor.start(
            timeout=10, callback=callback_detect_event).result()

        event_triggered = event['data']['type'] == expected_type and event['data']['path'] == path
        assert(event_triggered == should_be_triggered)

    except TimeoutError:
        if should_be_triggered:
            raise


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


parametrize_header = 'folder, should_be_triggered, applies_to_config'
parametrize_list = [
    (testdir1, True, 'ossec.*conf'),
    (testdir2, True, 'ossec_no_recursion.conf'),
    (testdir1_sub1, False, 'ossec_no_recursion.conf'),
    (testdir2_sub1, True, 'ossec_no_recursion.conf'),
    (testdir1_sub5, False, 'ossec_recursion_1.conf'),
    (testdir1_sub1, True, 'ossec_recursion_(1|5).*.conf'),
    (testdir1_sub5, True, 'ossec_recursion_5.conf'),
    (testdir1_sub320, True, 'ossec_recursion_320.conf')
]


@pytest.mark.parametrize(parametrize_header, parametrize_list)
@pytest.mark.parametrize('filename, mode, content', [
    ('testfile', 'w', "Sample content"),
    ('btestfile', 'wb', b"Sample content")
])
def test_recursion_level_add(folder, should_be_triggered, applies_to_config, filename, mode, content,
                             get_ossec_configuration, configure_environment, restart_wazuh):
    """Test Maximum_recursion_level functionality by creating files on several folders and checking if events are raised.

        This test is intended to be used with valid recursion configurations.

        :param folder string Directory where the file is being created
        :param should_be_triggered bool True if an event must be generated, False otherwise
        :param applies_to_config string RegEx to match the name of the configuration file where the test applies. If
                the configuration file does not match the test is skipped
        :param filename string Name of the file to be created
        :param mode string same as mode in open built-in function
        :param content string, bytes Content to fill the new file
    """

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    assert_event("added", os.path.join(folder, filename), should_be_triggered)


@pytest.mark.parametrize(parametrize_header, parametrize_list)
@pytest.mark.parametrize('filename', ['testfile', 'btestfile'])
def test_recursion_level_modify(folder, should_be_triggered, applies_to_config, filename,
                                get_ossec_configuration, configure_environment, restart_wazuh):
    """Test Maximum_recursion_level functionality by modifying files on several folders and checking if events are raised.

        This test is intended to be used with valid recursion configurations.

        :param folder string Directory where the file is being created
        :param should_be_triggered bool True if an event must be generated, False otherwise
        :param applies_to_config string RegEx to match the name of the configuration file where the test applies. If
                the configuration file does not match the test is skipped
        :param filename string Name of the file to be created
    """

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    os.chmod(os.path.join(folder, filename), stat.S_IRWXU)
    assert_event("modified", os.path.join(
        folder, filename), should_be_triggered)


@pytest.mark.parametrize(parametrize_header, parametrize_list)
@pytest.mark.parametrize('filename', ['testfile', 'btestfile'])
def test_recursion_level_delete(folder, should_be_triggered, applies_to_config, filename,
                                get_ossec_configuration, configure_environment, restart_wazuh):
    """Test Maximum_recursion_level functionality by removing files on several folders and checking if events are raised.

        This test is intended to be used with valid recursion configurations.

        :param folder string Directory where the file is being created
        :param should_be_triggered bool True if an event must be generated, False otherwise
        :param applies_to_config string RegEx to match the name of the configuration file where the test applies. If
                the configuration file does not match the test is skipped
        :param filename string Name of the file to be created
    """

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    os.remove(os.path.join(folder, filename))
    assert_event("deleted", os.path.join(
        folder, filename), should_be_triggered)