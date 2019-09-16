# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess
import time
from datetime import timedelta

import pytest

from wazuh_testing.fim import (ALERTS_FILE_PATH, LOG_FILE_PATH,
                               WAZUH_CONF_PATH, is_fim_scan_ended,
                               load_fim_alerts)
from wazuh_testing.tools import (TestEnvironment, TimeMachine, truncate_file,
                                 set_wazuh_conf, write_wazuh_conf,
                                 wait_for_condition)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories


# configurations

configurations = [{'section': 'syscheck',
                   'new_values': [{'disabled': 'no'},
                                  {'directories': '/testdir1,/testdir2,/noexists'}],
                   'new_attributes': [{'directories': [{'check_all': 'yes'},
                                                       {'realtime': 'yes'}]}],
                   'checks': []}
                  ]


# functions

def restart_wazuh():
    truncate_file(LOG_FILE_PATH)
    p = subprocess.Popen(["service", "wazuh-manager", "restart"])
    p.wait()
    wait_for_condition(lambda: is_fim_scan_ended() > -1, timeout=60)
    time.sleep(11)


# fixtures

@pytest.fixture(scope='module', params=configurations, autouse=True)
def configure_environment(request):
    """Configure a custom environment for testing.

    :param params: List with values to customize Wazuh configuration
    """
    print(f"Setting a custom environment: {str(request.param)}")

    test_environment = TestEnvironment(request.param.get('section'),
                                       request.param.get('new_values'),
                                       request.param.get('new_attributes'),
                                       request.param.get('checks')
                                       )
    # set new configuration
    set_wazuh_conf(test_environment.new_conf)

    # create test directories
    test_directories = getattr(request.module, 'test_directories')
    for test_dir in test_directories:
        os.mkdir(test_dir)

    yield

    # remove created folders
    for test_dir in test_directories:
        shutil.rmtree(test_dir)
    # restore previous configuration
    write_wazuh_conf(test_environment.backup_conf)
    restart_wazuh()


# tests

@pytest.mark.parametrize('folder, filename, mode, content', [
    (testdir1, 'testfile', 'w', "Sample content"),
    (testdir1, 'btestfile', 'wb', b"Sample content"),
    (testdir2, 'testfile', 'w', ""),
    (testdir2, "btestfile", "wb", b"")
])
def _test_regular_file(folder, filename, mode, content):
    """Checks if a regular file creation is detected by syscheck"""

    # Create text files
    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    # Wait for FIM scan to finish
    wait_for_condition(lambda: is_fim_scan_ended() > -1, timeout=60)
    time.sleep(11)
    # Wait until alerts are generated
    wait_for_condition(lambda: len(load_fim_alerts(n_last=1)) == 1, timeout=5)

    truncate_file(ALERTS_FILE_PATH)
