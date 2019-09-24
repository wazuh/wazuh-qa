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
                               callback_detect_end_scan)
from wazuh_testing.tools import (FileMonitor, TestEnvironment, truncate_file,
                                 wait_for_condition, write_wazuh_conf)

# functions

def set_wazuh_conf(new_conf, request):
    """Set a new Wazuh configuration. It restarts Wazuh."""
    write_wazuh_conf(new_conf)
    restart_wazuh(request)


# fixtures

@pytest.fixture(scope='module')
def restart_wazuh(get_configuration, request):
    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Restart Wazuh and wait for the command to end
    p = subprocess.Popen(["service", "wazuh-manager", "restart"])
    p.wait()


@pytest.fixture(scope='module')
def wait_for_initial_scan(get_configuration, request):
    # Wait for initial FIM scan to end
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    file_monitor.start(timeout=60, callback=callback_detect_end_scan)

    # Add additional sleep to avoid changing system clock issues (TO BE REMOVED when syscheck has not sleeps anymore)
    time.sleep(11)


@pytest.fixture(scope='module')
def configure_environment(get_configuration, request):
    """Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration."""
    print(f"Setting a custom environment: {str(get_configuration)}")

    test_environment = TestEnvironment(get_configuration.get('section'),
                                       get_configuration.get('elements'),
                                       get_configuration.get('identifiers')
                                       )

    # create test directories
    test_directories = getattr(request.module, 'test_directories')
    for test_dir in test_directories:
        os.mkdir(test_dir)

    # set new configuration
    write_wazuh_conf(test_environment.new_conf)

    yield

    # remove created folders (parents)
    parent_directories = set([os.path.join('/', test_dir.split('/')[1]) for
                              test_dir in test_directories])
    for parent_directory in parent_directories:
        shutil.rmtree(parent_directory)

    # restore previous configuration
    write_wazuh_conf(test_environment.backup_conf)
