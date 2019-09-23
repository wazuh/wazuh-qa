# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import pytest
import re

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

def create_folder_hierarchy(num_subdirectories):
    path = "/testdir1"
    for n in range(1, num_subdirectories):
        path = os.path.join(path, "subdir" + str(n))
    return path


test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir1', 'subdir1'),
                    os.path.join('/', 'testdir2', 'subdir1'),
                    create_folder_hierarchy(5),
                    create_folder_hierarchy(319)
                    ]
testdir1, testdir2, testdir1_sub1, testdir2_sub1, testdir1_sub5, testdir1_sub320 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param

@pytest.mark.parametrize('folder, filename, mode, content, should_be_triggered, applies_to_config', [
    (testdir1, 'testfile', 'w', "Sample content", True, 'ossec.*conf'),
    (testdir1, 'btestfile', 'wb', b"Sample content", True, 'ossec.*conf'),
    (testdir2, 'testfile', 'w', "Sample content", True, 'ossec_no_recursion.conf'),
    (testdir2, 'btestfile', 'wb', b"Sample content", True, 'ossec_no_recursion.conf'),
    (testdir1_sub1, 'testfile', 'w', "", False, 'ossec_no_recursion.conf'),
    (testdir1_sub1, 'testfile', 'wb', b"", False, 'ossec_no_recursion.conf'),
    (testdir2_sub1, 'testfile', 'w', "", True, 'ossec_no_recursion.conf'),
    (testdir2_sub1, 'testfile', 'wb', b"", True, 'ossec_no_recursion.conf'),
    (testdir1_sub5, 'testfile', 'w', "", False, 'ossec_recursion_1.conf'),
    (testdir1_sub5, "btestfile", "wb", b"", False, 'ossec_recursion_1.conf'),
    (testdir1_sub1, 'testfile', 'w', "", True, 'ossec_recursion_(1|5).*.conf'),
    (testdir1_sub1, 'btestfile', 'wb', b"", True, 'ossec_valid_recursion_(1|5).*.conf'),
    (testdir1_sub5, 'testfile', 'w', "", True, 'ossec_recursion_5.conf'),
    (testdir1_sub5, "btestfile", "wb", b"", True, 'ossec_recursion_5.conf'),
    (testdir1_sub320, 'testfile', 'w', "Sample content", True, 'ossec_recursion_320.conf'),
    (testdir1_sub320, 'btestfile', 'wb', b"Sample content", True, 'ossec_recursion_320.conf')
])

def test_maximum_recursion_level(folder, filename, mode, content, should_be_triggered, applies_to_config,
                                 get_ossec_configuration, configure_environment, restart_wazuh):
    """Checks files inside directories recursively according to maximum_recursion_level

        This test is intended to be used with valid recursion configurations.

        :param folder string Directory where the file is being created
        :param filename string Name of the file to be created
        :param mode string same as mode in open built-in function
        :param content string, bytes Content to fill the new file
        :param should_be_triggered bool True if an event must be generated, False otherwise
        :param applies_to_config string RegEx to match the name of the configuration file where the test applies. If
                the configuration file does not match the test is skipped
    """

    if not re.search(applies_to_config, get_ossec_configuration):
        pytest.skip("Does not apply to this config file")

    # Create text files
    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    # Fetch the n_regular expected events
    try:
        event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()

        event_triggered = event['data']['type'] in ["added", "modified"] and event['data']['path'] == os.path.join(folder, filename)
        assert(event_triggered == should_be_triggered)

    except TimeoutError:
        if should_be_triggered:
            raise
