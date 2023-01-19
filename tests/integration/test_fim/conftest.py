# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing import (global_parameters, LOG_FILE_PATH, WAZUH_SERVICES_START, WAZUH_SERVICES_STOP,
                           WAZUH_LOG_MONITOR)
from wazuh_testing.tools.configuration import (get_wazuh_local_internal_options, set_wazuh_local_internal_options,
                                               create_local_internal_options)
from wazuh_testing.tools.file import truncate_file, delete_path_recursively
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.modules.fim import (registry_parser, KEY_WOW64_64KEY, WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY,
                                       SYNC_INTERVAL_VALUE, FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS)
from wazuh_testing.modules.fim import event_monitor as evm
from wazuh_testing.modules.fim.utils import create_registry, delete_registry


@pytest.fixture()
def create_key(request):
    """
    Fixture that create the test key And then delete the key and truncate the file. The aim of this fixture is to avoid
    false positives if the manager still has the test key in it's DB.
    """
    control_service(WAZUH_SERVICES_STOP)
    create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], MONITORED_KEY, KEY_WOW64_64KEY)

    yield
    delete_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], MONITORED_KEY, KEY_WOW64_64KEY)
    control_service(WAZUH_SERVICES_STOP)
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, WAZUH_LOG_MONITOR, file_monitor)
    control_service(WAZUH_SERVICES_START)

    # wait until the sync is done.
    file_monitor.start(timeout=SYNC_INTERVAL_VALUE + global_parameters.default_timeout,
                       callback=evm.callback_detect_registry_integrity_clear_event,
                       error_message='Did not receive expected "integrity clear" event')


@pytest.fixture()
def wait_fim_start_function(configuration):
    """ Wait for realtime start, whodata start or end of initial FIM scan.

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
    """
    file_monitor = FileMonitor(LOG_FILE_PATH)
    mode_key = 'fim_mode' if 'fim_mode2' not in configuration else 'fim_mode2'

    try:
        if configuration[mode_key] == 'realtime':
            evm.detect_realtime_start(file_monitor)
        elif configuration[mode_key] == 'whodata':
            evm.detect_whodata_start(file_monitor)
        else:  # scheduled
            evm.detect_initial_scan(file_monitor)
    except KeyError:
        evm.detect_initial_scan(file_monitor)


@pytest.fixture()
def restart_syscheck_function():
    """
    Restart syscheckd daemon.
    """
    control_service("stop", daemon="wazuh-syscheckd")
    truncate_file(LOG_FILE_PATH)
    control_service("start", daemon="wazuh-syscheckd")


@pytest.fixture(scope="module")
def create_monitored_folders_module(test_folders):
    """
    Create the folders that will be monitored and delete them at the end.
    Args:
        test_folders(list): List of folders to create and delete
    """
    for folder in test_folders:
        if os.path.exists(folder):
            delete_path_recursively(folder)
        os.mkdir(folder)
    yield
    for folder in test_folders:
        delete_path_recursively(folder)
