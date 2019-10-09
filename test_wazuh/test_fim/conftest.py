# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, detect_initial_scan)
from wazuh_testing.tools import (FileMonitor, get_wazuh_conf,
                                 set_section_wazuh_conf, truncate_file,
                                 restart_wazuh_service, write_wazuh_conf)


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
    restart_wazuh_service()


@pytest.fixture(scope='module')
def wait_for_initial_scan(get_configuration, request):
    # Wait for initial FIM scan to end
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    detect_initial_scan(file_monitor)


@pytest.fixture(scope='module')
def configure_environment(get_configuration, request):
    """Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration."""
    print(f"Setting a custom environment: {str(get_configuration)}")

    # save current configuration
    backup_config = get_wazuh_conf()
    # configuration for testing
    test_config = set_section_wazuh_conf(get_configuration.get('section'),
                                         get_configuration.get('elements'))

    # create test directories
    test_directories = getattr(request.module, 'test_directories')
    for test_dir in test_directories:
        os.makedirs(test_dir, exist_ok=True)

    # set new configuration
    write_wazuh_conf(test_config)

    yield

    # remove created folders (parents)
    for test_dir in test_directories:
        shutil.rmtree(test_dir, ignore_errors=True)

    # restore previous configuration
    write_wazuh_conf(backup_config)
