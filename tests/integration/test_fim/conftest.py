# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re
import subprocess
import pytest

from distro import id
from wazuh_testing import global_parameters
from wazuh_testing.tools.services import control_service
from wazuh_testing.fim import (create_registry, registry_parser, KEY_WOW64_64KEY, delete_registry,
                               LOG_FILE_PATH, callback_detect_registry_integrity_clear_event)
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.fim_module.fim_variables import WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, SYNC_INTERVAL_VALUE
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
        raise ValueError(f"Linux distro ({linux_distro}) not supported for uninstall/install audit")

    # Install audit and start the service
    process = subprocess.run([package_management, "install", audit, option], check=True)
    process = subprocess.run(["service", "auditd", "start"], check=True)
