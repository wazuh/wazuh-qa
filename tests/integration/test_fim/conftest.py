# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.tools.services import control_service
from wazuh_testing.fim import create_registry, registry_parser, KEY_WOW64_64KEY, delete_registry, LOG_FILE_PATH, callback_detect_registry_integrity_clear_event
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.fim_module.fim_variables import WINDOWS_HKEY_LOCAL_MACHINE, MONITORED_KEY, SYNC_INTERVAL_VALUE
from wazuh_testing.tools.monitoring import FileMonitor


@pytest.fixture(scope='function')
def create_key(request):
    """Fixture that create the test key And then delete the key and truncate the file. The aim of this
       fixture is to avoid false positives if the manager still has the test  key
       in it's DB.
    """
    control_service('stop')
    create_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], MONITORED_KEY, KEY_WOW64_64KEY)

    yield
    delete_registry(registry_parser[WINDOWS_HKEY_LOCAL_MACHINE], MONITORED_KEY, KEY_WOW64_64KEY)
    control_service('stop')
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start')

    # wait until the sync is done.
    file_monitor.start(timeout= SYNC_INTERVAL_VALUE + global_parameters.default_timeout,
                            callback=callback_detect_registry_integrity_clear_event,
                            error_message='Did not receive expected "integrity clear" event')
