# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, detect_initial_scan, detect_realtime_start, detect_whodata_start
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service


@pytest.fixture(scope='module')
def restart_syscheckd(get_configuration, request):
    """
    Reset ossec.log and start a new monitor.
    """
    control_service('stop', daemon='ossec-syscheckd')
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon='ossec-syscheckd')


@pytest.fixture(scope='module')
def wait_for_syscheck_start(get_configuration, request):
    """
    Wait for initial FIM scan to end. If realtime or whodata are enabled, it will wait for their start too.
    """
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    detect_initial_scan(file_monitor)

    if get_configuration['metadata']['fim_mode'] == 'realtime':
        detect_realtime_start(file_monitor)
    elif get_configuration['metadata']['fim_mode'] == 'whodata':
        detect_whodata_start(file_monitor)
