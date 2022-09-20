# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re
import subprocess
import time
import pytest

from distro import id
from wazuh_testing import global_parameters
from wazuh_testing.tools.configuration import (get_wazuh_local_internal_options, set_wazuh_local_internal_options,
                                               create_local_internal_options)
from wazuh_testing.tools.services import control_service
from wazuh_testing.fim import (create_registry, registry_parser, KEY_WOW64_64KEY, delete_registry, create_file,
                               LOG_FILE_PATH, callback_detect_registry_integrity_clear_event, REGULAR)

from wazuh_testing.tools.file import truncate_file, delete_path_recursively
from wazuh_testing.modules.fim import (WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, SYNC_INTERVAL_VALUE,
                                       FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS, MONITORED_DIR_1)
from wazuh_testing.modules.fim.event_monitor import detect_whodata_start, detect_realtime_start, detect_initial_scan
from wazuh_testing.wazuh_variables import WAZUH_SERVICES_START, WAZUH_SERVICES_STOP, WAZUH_LOG_MONITOR
from wazuh_testing.tools.monitoring import FileMonitor


@pytest.fixture(scope='function')
def create_key(request):
    """Fixture that create the test key And then delete the key and truncate the file. The aim of this
       fixture is to avoid false positives if the manager still has the test  key
       in it's DB.
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
                       callback=callback_detect_registry_integrity_clear_event,
                       error_message='Did not receive expected "integrity clear" event')


@pytest.fixture(scope='function')
def create_files_in_folder(files_number):
    """Create files in monitored folder and files"""

    for file in range(0, files_number):
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


@pytest.fixture(scope='session')
def configure_local_internal_options_fim():
    """Fixture to configure the local internal options file."""

    # Backup the old local internal options
    backup_local_internal_options = get_wazuh_local_internal_options()

    # Set the new local internal options configuration
    set_wazuh_local_internal_options(create_local_internal_options(FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS))

    yield

    # Backup the old local internal options cofiguration
    set_wazuh_local_internal_options(backup_local_internal_options)


@pytest.fixture(scope='function')
def set_wazuh_configuration_fim(configuration, set_wazuh_configuration, configure_local_internal_options_fim):
    """Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
        set_wazuh_configuration (fixture): Set the wazuh configuration according to the configuration data.
        configure_local_internal_options_fim (fixture): Set the local_internal_options.conf file.
    """
    yield


@pytest.fixture(scope='function')
def wait_for_fim_start_function(configuration):
    """
    Wait for realtime start, whodata start or end of initial FIM scan.
    """
    file_monitor = FileMonitor(LOG_FILE_PATH)
    mode_key = 'fim_mode' if 'fim_mode2' not in configuration else 'fim_mode2'

    try:
        if configuration[mode_key] == 'realtime':
            detect_realtime_start(file_monitor)
        elif configuration[mode_key] == 'whodata':
            detect_whodata_start(file_monitor)
        else:  # scheduled
            detect_initial_scan(file_monitor)
    except KeyError:
        detect_initial_scan(file_monitor)


@pytest.fixture(scope="function")
def restart_syscheck_function():
    """
    Restart syscheckd daemon.
    """
    control_service("stop", daemon="wazuh-syscheckd")
    truncate_file(LOG_FILE_PATH)
    control_service("start", daemon="wazuh-syscheckd")
