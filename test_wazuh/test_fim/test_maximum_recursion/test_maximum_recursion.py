# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir1', 'subdir1'),
                    os.path.join('/', 'testdir1', 'subdir1', 'subdir2', 'subdir3', 'subdir4', 'subdir5')
                    ]
testdir1, testdir_sub1, testdir_sub5 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param

@pytest.mark.parametrize('folder, filename, mode, content, triggers_event, applies_to_config', [
    (testdir1, 'testfile', 'w', "Sample content", True, 'ossec.*conf'),
    (testdir1, 'btestfile', 'wb', b"Sample content", True, 'ossec.*conf'),

    (testdir_sub1, 'testfile', 'w', "", False, 'ossec_no_recursion.conf'),
    (testdir_sub1, "btestfile", "wb", b"", False, 'ossec_no_recursion.conf'),

    (testdir_sub1, 'testfile', 'w', "", False, 'ossec_valid_recursion_1.conf'),
    (testdir_sub1, "btestfile", "wb", b"", False, 'ossec_valid_recursion_1.conf'),

    (testdir_sub1, 'testfile', 'w', "", True, 'ossec_valid_recursion_2.conf'),
    (testdir_sub1, "btestfile", "wb", b"", True, 'ossec_valid_recursion_2.conf'),
    (testdir_sub5, 'testfile', 'w', "", False, 'ossec_valid_recursion_2.conf'),
    (testdir_sub5, "btestfile", "wb", b"", False, 'ossec_valid_recursion_2.conf'),

    (testdir_sub1, 'testfile', 'w', "", True, 'ossec_valid_recursion_3.conf'),
    (testdir_sub1, "btestfile", "wb", b"", True, 'ossec_valid_recursion_3.conf'),
    (testdir_sub5, 'testfile', 'w', "", True, 'ossec_valid_recursion_3.conf'),
    (testdir_sub5, "btestfile", "wb", b"", True, 'ossec_valid_recursion_3.conf'),
])

def test_maximum_recursion_level(folder, filename, mode, content, triggers_event, applies_to_config,
                             get_ossec_configuration, configure_environment, restart_wazuh):
    """Checks files inside directories recursively according to maximum_recursion_level

        This test is intended to be used with valid recursion configurations.

        :param folder string Directory where the file is being created
        :param filename string Name of the file to be created
        :param mode string same as mode in open built-in function
        :param content string, bytes Content to fill the new file
        :param triggers_event bool True if an event must be generated, False otherwise
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
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        assert(event['data']['type'] == 'added')
        assert(event['data']['path'] == os.path.join(folder, filename))
    except TimeoutError:
        if triggers_event:
            raise
