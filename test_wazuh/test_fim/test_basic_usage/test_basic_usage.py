# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess
import time
from datetime import timedelta

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_end_scan,
                               callback_detect_event)
from wazuh_testing.tools import (FileMonitor, TestEnvironment, TimeMachine,
                                 set_wazuh_conf, wait_for_condition,
                                 write_wazuh_conf)


# variables


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories


# configurations

configurations = [{'section': 'syscheck',
                   'new_values': [{'disabled': 'no'},
                                  {'directories': '/testdir1,/testdir2,/noexists'}],
                   'new_attributes': [{'directories': [{'check_all': 'yes'}]}],
                   'checks': []},
                  {'section': 'syscheck',
                   'new_values': [{'disabled': 'no'},
                                  {'frequency': '21600'},
                                  {'directories': '/testdir1,/testdir2,/noexists'}],
                   'new_attributes': [{'directories': [{'check_all': 'yes'}]}],
                   'checks': []}
                  ]


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

@pytest.mark.parametrize('folder, filename, mode, content', [
    (testdir1, 'testfile', 'w', "Sample content"),
    (testdir1, 'btestfile', 'wb', b"Sample content"),
    (testdir2, 'testfile', 'w', ""),
    (testdir2, "btestfile", "wb", b"")
])
def test_regular_file(folder, filename, mode, content, configure_environment):
    """Checks if a regular file creation is detected by syscheck"""
    # Create text files
    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    # Go ahead in time to let syscheck perform a new scan
    print("Muevo el reloj 13 horas al futuro")
    TimeMachine.travel_to_future(timedelta(hours=13))

    # Wait until event is detected
    print("Espero a que salte el evento")
    wazuh_log_monitor.start(timeout=10, callback=callback_detect_event)

    # Wait for FIM scan to finish
    print("Espero a que termine el scan")
    wazuh_log_monitor.start(timeout=10, callback=callback_detect_end_scan)
    print("Espero 11 segundos")
    time.sleep(11)
