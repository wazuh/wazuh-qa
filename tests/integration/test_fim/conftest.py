# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import subprocess
import time
import pytest

from distro import id
from wazuh_testing import (global_parameters, LOG_FILE_PATH, REGULAR, WAZUH_SERVICES_START, WAZUH_SERVICES_STOP,
                           WAZUH_LOG_MONITOR)
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file, delete_path_recursively, create_file
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing.modules.fim import (WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, SYNC_INTERVAL_VALUE, KEY_WOW64_64KEY,
                                       MONITORED_DIR_1, registry_parser)
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
def create_files_in_folder(metadata):
    """Create files in monitored folder and files"""

    for file in range(0, metadata['files']):
        create_file(REGULAR, MONITORED_DIR_1, f"test_file_{time.time()}_{file}")

    yield

    delete_path_recursively(MONITORED_DIR_1)


@pytest.fixture(scope='module')
def install_audit(get_configuration):
    """Install auditd before test"""

    # Check distro
    linux_distro = id()

    if re.match(linux_distro, "centos"):
        package_management = "yum"
        audit = "audit"
        option = "--assumeyes"
    elif re.match(linux_distro, "ubuntu") or re.match(linux_distro, "debian"):
        package_management = "apt-get"
        audit = "auditd"
        option = "--yes"
    else:
        # Install audit and start the service
        process = subprocess.run([package_management, "install", audit, option], check=True)
        process = subprocess.run(["service", "auditd", "start"], check=True)


@pytest.fixture()
def wait_fim_start(configuration):
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
def wait_syscheck_start(metadata):
    """ Wait for realtime start, whodata start or end of initial FIM scan.
    Args:
        metadata (dict): Test additional metadata
    """
    file_monitor = FileMonitor(LOG_FILE_PATH)
    mode_key = 'fim_mode' if 'fim_mode2' not in metadata else 'fim_mode2'

    try:
        if metadata[mode_key] == 'realtime':
            evm.detect_realtime_start(file_monitor)
        elif metadata[mode_key] == 'whodata':
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


@pytest.fixture()
def create_monitored_folders(test_folders):
    """
    Create the folders that will be monitored and delete them at the end.

    Args:
        test_folders(list): List of folders to create and delete
    """
    for folder in test_folders:
        if not os.path.exists(folder):
            os.mkdir(folder, mode=0o0777)

    yield

    for folder in test_folders:
        if os.path.exists(folder):
            delete_path_recursively(folder)


@pytest.fixture(scope='module')
def create_monitored_folders_module(test_folders):
    """
    Create the folders that will be monitored and delete them at the end.

    Args:
        test_folders(list): List of folders to create and delete
    """
    for folder in test_folders:
        if not os.path.exists(folder):
            os.mkdir(folder, mode=0o0777)

    yield

    for folder in test_folders:
        if os.path.exists(folder):
            delete_path_recursively(folder)


@pytest.fixture()
def restore_win_whodata_policies(policies_file):

    yield

    command = f"auditpol /restore /file:{policies_file}"
    run_local_command_returning_output(command)
