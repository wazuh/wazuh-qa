# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import re
import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir1', 'subdir'),
                    os.path.join('/', 'testdir1', 'ignore_this'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_ignore, testdir2, testdir2_sub = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.parametrize('folder, filename, mode, content, triggers_event, applies_to_config', [
    (testdir1, 'testfile', 'w', "Sample content", True, 'ossec.*conf'),
    (testdir1, 'btestfile', 'wb', b"Sample content", True, 'ossec.*conf'),
    (testdir1, 'testfile2', 'w', "", True, 'ossec.*conf'),
    (testdir1, "btestfile2", "wb", b"", True, 'ossec.*conf'),
    (testdir1, "btestfile2.ignore", "wb", b"", False, 'ossec_sregex_(1|2|3).*conf'),
    (testdir1, "btestfile2.ignored", "wb", b"", True, 'ossec.*conf'),
    (testdir1_sub, 'testfile', 'w', "Sample content", True, 'ossec.*conf'),
    (testdir1_sub, 'btestfile', 'wb', b"Sample content", True, 'ossec.*conf'),
    (testdir1_sub, 'testfile2', 'w', "", True, 'ossec.*conf'),
    (testdir1_sub, "btestfile2", "wb", b"", True, 'ossec.*conf'),
    (testdir1_sub, ".ignore.btestfile", "wb", b"", True, 'ossec.*conf'),
    (testdir2, "another.ignore", "wb", b"other content", False, 'ossec_sregex_(1|2|3).*conf'),
    (testdir2, "another.ignored", "wb", b"other content", True, 'ossec_sregex.*conf'),
    (testdir2_sub, "another.ignore", "wb", b"other content", False, 'ossec_sregex_(1|2|3).*conf'),
    (testdir2_sub, "another.ignored", "wb", b"other content", True, 'ossec_sregex.*conf'),
    (testdir2, "another.ignored2", "w", "", True, r'ossec.*conf'),
    (testdir2, "another.ignore2", "w", "", False, r'ossec_sregex_(2|3)\.conf'),
    (testdir1, 'ignore_prefix_test.txt', "w", "test", True, 'ossec_sregex_(1|2|3|4).*conf'),
    (testdir1, 'ignore_prefix_test.txt', "w", "test", False, 'ossec_sregex_5.conf')
])
def test_ignore_subdirectory(folder, filename, mode, content, triggers_event, applies_to_config,
                             get_ossec_configuration, configure_environment, restart_wazuh):
    """Checks files are ignored in subdirectory according to configuration

       This test is intended to be used with valid ignore configurations

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
        assert triggers_event
        assert (event['data']['type'] == 'added')
        assert (event['data']['path'] == os.path.join(folder, filename))
    except TimeoutError:
        if triggers_event:
            raise
