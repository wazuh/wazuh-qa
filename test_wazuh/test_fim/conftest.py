# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import shutil
import subprocess
import time

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, WAZUH_CONF_PATH,
                               callback_detect_end_scan, is_fim_scan_ended)
from wazuh_testing.tools import (FileMonitor, TestEnvironment, set_wazuh_conf,
                                 truncate_file, wait_for_condition,
                                 write_wazuh_conf)


# variables

test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
testdir1, testdir2 = test_directories


# functions

def restart_wazuh():
    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    # setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Restart Wazuh and wait for the command to end
    p = subprocess.Popen(["service", "wazuh-manager", "restart"])
    p.wait()

    # Wait for initial FIM scan to end
    file_monitor.start(timeout=60, callback=callback_detect_end_scan)

    # Add additional sleep to avoid changing system clock issues (TO BE REMOVED when syscheck has not sleeps anymore)
    time.sleep(11)


# fixtures

@pytest.fixture(scope='module')
def configure_environment(get_configuration, request):
    """Configure a custom environment for testing.

    :param params: List with values to customize Wazuh configuration
    """
    print(f"Setting a custom environment: {str(get_configuration)}")

    test_environment = TestEnvironment(get_configuration.get('section'),
                                       get_configuration.get('new_values'),
                                       get_configuration.get('new_attributes'),
                                       get_configuration.get('checks')
                                       )
    # set new configuration
    set_wazuh_conf(test_environment.new_conf)

    # create test directories
    for test_dir in test_directories:
        os.mkdir(test_dir)

    yield

    # remove created folders
    for test_dir in test_directories:
        shutil.rmtree(test_dir)
    # restore previous configuration
    write_wazuh_conf(test_environment.backup_conf)
    restart_wazuh()
