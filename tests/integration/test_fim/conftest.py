# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess
import sys

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, detect_initial_scan
from wazuh_testing.tools.configuration import get_wazuh_conf, write_wazuh_conf, set_section_wazuh_conf
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.time import TimeMachine


@pytest.fixture(scope='module')
def restart_syscheckd(get_configuration, request):
    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('restart', daemon='ossec-syscheckd')


@pytest.fixture(scope='module')
def wait_for_initial_scan(get_configuration, request):
    # Wait for initial FIM scan to end
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    detect_initial_scan(file_monitor)


@pytest.fixture(scope='function', autouse=True)
def skip_scheduled(get_configuration):
    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        pytest.skip('Skipping Scheduled test')


@pytest.fixture(scope='module')
def configure_environment(get_configuration, request):
    """Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration."""

    # save current configuration
    backup_config = get_wazuh_conf()

    # configuration for testing
    test_config = set_section_wazuh_conf(get_configuration.get('section'),
                                         get_configuration.get('elements'))

    # create test directories
    if hasattr(request.module, 'test_directories'):
        test_directories = getattr(request.module, 'test_directories')
        for test_dir in test_directories:
            os.makedirs(test_dir, exist_ok=True, mode=0o777)

    # set new configuration
    write_wazuh_conf(test_config)

    # Change Windows Date format to ensure TimeMachine will work properly
    if sys.platform == 'win32':
        subprocess.call('reg add "HKCU\\Control Panel\\International" /f /v sShortDate /t REG_SZ /d "dd/MM/yyyy" >nul',
                        shell=True)

    # Call extra functions before yield
    if hasattr(request.module, 'extra_configuration_before_yield'):
        func = getattr(request.module, 'extra_configuration_before_yield')
        func()

    yield

    TimeMachine.time_rollback()

    # remove created folders (parents)
    if sys.platform == 'win32':
        control_service('stop')

    if hasattr(request.module, 'test_directories'):
        for test_dir in test_directories:
            shutil.rmtree(test_dir, ignore_errors=True)

    if sys.platform == 'win32':
        control_service('start')

    # restore previous configuration
    write_wazuh_conf(backup_config)

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    if hasattr(request.module, 'force_restart_after_restoring'):
        if getattr(request.module, 'force_restart_after_restoring'):
            control_service('restart')
